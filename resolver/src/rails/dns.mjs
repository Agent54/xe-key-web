// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Minimal RFC 1035 wire codec: enough for PKARR packets (TXT answers).
// decode() follows compression pointers with loop protection and bounds
// checks on every read; encode() never compresses.

import { utf8, utf8Decoder } from '../encoding.mjs';

export const TYPE_TXT = 16;
export const CLASS_IN = 1;

export class DnsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DnsError';
  }
}

function encodeName(name) {
  const out = [];
  for (const label of name.replace(/\.$/, '').split('.')) {
    if (!label) continue;
    const b = utf8.encode(label);
    if (b.length > 63) throw new DnsError(`label too long: ${label}`);
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}

/**
 * Encode a response packet with TXT answers.
 * @param {{ answers: { name: string, ttl?: number, txt: string[] }[] }} packet
 */
export function encodePacket({ answers }) {
  const out = [0, 0, 0x84, 0, 0, 0, (answers.length >> 8) & 0xff, answers.length & 0xff, 0, 0, 0, 0];
  for (const a of answers) {
    out.push(...encodeName(a.name));
    out.push(0, TYPE_TXT, 0, CLASS_IN);
    const ttl = a.ttl ?? 300;
    out.push((ttl >>> 24) & 0xff, (ttl >>> 16) & 0xff, (ttl >>> 8) & 0xff, ttl & 0xff);
    const rdata = [];
    for (const s of a.txt) {
      const b = utf8.encode(s);
      if (b.length > 255) throw new DnsError('TXT character-string longer than 255 bytes');
      rdata.push(b.length, ...b);
    }
    out.push((rdata.length >> 8) & 0xff, rdata.length & 0xff, ...rdata);
  }
  return Uint8Array.from(out);
}

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let jumped = false;
  let end = offset;
  for (let hops = 0; hops < 64; hops++) {
    if (pos >= buf.length) throw new DnsError('name runs past end of packet');
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) end = pos + 1;
      return { name: labels.join('.'), end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new DnsError('truncated compression pointer');
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (target >= pos) throw new DnsError('forward compression pointer');
      if (!jumped) end = pos + 2;
      jumped = true;
      pos = target;
      continue;
    }
    if (len > 63) throw new DnsError('bad label length');
    if (pos + 1 + len > buf.length) throw new DnsError('label runs past end of packet');
    labels.push(utf8Decoder.decode(buf.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  throw new DnsError('too many compression hops');
}

/** Decode answers (all types; TXT rdata is split into strings). */
export function decodePacket(buf) {
  if (!(buf instanceof Uint8Array) || buf.length < 12) throw new DnsError('packet too short');
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const qd = view.getUint16(4);
  const an = view.getUint16(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) {
    pos = readName(buf, pos).end + 4;
    if (pos > buf.length) throw new DnsError('truncated question');
  }
  const answers = [];
  for (let i = 0; i < an; i++) {
    const { name, end } = readName(buf, pos);
    pos = end;
    if (pos + 10 > buf.length) throw new DnsError('truncated resource record');
    const type = view.getUint16(pos);
    const cls = view.getUint16(pos + 2);
    const ttl = view.getUint32(pos + 4);
    const rdlen = view.getUint16(pos + 8);
    pos += 10;
    if (pos + rdlen > buf.length) throw new DnsError('rdata runs past end of packet');
    const rdata = buf.subarray(pos, pos + rdlen);
    pos += rdlen;
    const answer = { name: name.toLowerCase(), type, class: cls, ttl };
    if (type === TYPE_TXT) {
      const txt = [];
      for (let p = 0; p < rdata.length;) {
        const len = rdata[p];
        if (p + 1 + len > rdata.length) throw new DnsError('TXT string runs past rdata');
        txt.push(utf8Decoder.decode(rdata.subarray(p + 1, p + 1 + len)));
        p += 1 + len;
      }
      answer.txt = txt;
    }
    answers.push(answer);
  }
  return { answers };
}
