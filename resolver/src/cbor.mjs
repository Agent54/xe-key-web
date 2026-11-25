// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Deterministically encoded CBOR (RFC 8949 §4.2.1, "core deterministic"),
// restricted to the data model key-web records use:
//   unsigned/negative integers, byte strings, text strings, arrays,
//   maps with text keys, true/false/null.
// Floats, tags, undefined and indefinite lengths are rejected.
//
// decode() is strict: it re-encodes its result and requires the input bytes
// to be byte-identical, so a signed record has exactly one valid encoding.

import { concat, equalBytes, utf8, utf8Decoder } from './encoding.mjs';

const MAX_DEPTH = 16;

export class CborError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CborError';
  }
}

function head(major, value) {
  const big = BigInt(value);
  if (big < 0n) throw new CborError('negative length/argument');
  if (big < 24n) return Uint8Array.of((major << 5) | Number(big));
  if (big < 0x100n) return Uint8Array.of((major << 5) | 24, Number(big));
  if (big < 0x10000n) {
    const b = new Uint8Array(3);
    b[0] = (major << 5) | 25;
    new DataView(b.buffer).setUint16(1, Number(big));
    return b;
  }
  if (big < 0x100000000n) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    new DataView(b.buffer).setUint32(1, Number(big));
    return b;
  }
  if (big < 0x10000000000000000n) {
    const b = new Uint8Array(9);
    b[0] = (major << 5) | 27;
    new DataView(b.buffer).setBigUint64(1, big);
    return b;
  }
  throw new CborError('integer out of range');
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function encodeItem(value, depth) {
  if (depth > MAX_DEPTH) throw new CborError('nesting too deep');
  if (value === null) return Uint8Array.of(0xf6);
  if (value === true) return Uint8Array.of(0xf5);
  if (value === false) return Uint8Array.of(0xf4);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CborError('only safe integers are supported');
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === 'bigint') {
    return value >= 0n ? head(0, value) : head(1, -1n - value);
  }
  if (typeof value === 'string') {
    const b = utf8.encode(value);
    return concat(head(3, b.length), b);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) {
    return concat(head(4, value.length), ...value.map((v) => encodeItem(v, depth + 1)));
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined);
    const encoded = entries.map(([k, v]) => [encodeItem(k, depth + 1), encodeItem(v, depth + 1)]);
    encoded.sort((x, y) => compareBytes(x[0], y[0]));
    return concat(head(5, encoded.length), ...encoded.flat());
  }
  throw new CborError(`unsupported type: ${typeof value}`);
}

/** Encode `value` as deterministic CBOR. `undefined` map values are omitted. */
export function encode(value) {
  return encodeItem(value, 0);
}

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.pos = 0;
  }

  need(n) {
    if (this.pos + n > this.buf.length) throw new CborError('unexpected end of input');
  }

  u8() {
    this.need(1);
    return this.buf[this.pos++];
  }

  argument(info) {
    if (info < 24) return BigInt(info);
    if (info === 24) return BigInt(this.u8());
    if (info === 25) { this.need(2); const v = this.view.getUint16(this.pos); this.pos += 2; return BigInt(v); }
    if (info === 26) { this.need(4); const v = this.view.getUint32(this.pos); this.pos += 4; return BigInt(v); }
    if (info === 27) { this.need(8); const v = this.view.getBigUint64(this.pos); this.pos += 8; return v; }
    throw new CborError('indefinite lengths and reserved values are not allowed');
  }

  length(info) {
    const n = this.argument(info);
    if (n > BigInt(this.buf.length - this.pos)) throw new CborError('length exceeds input');
    return Number(n);
  }

  item(depth) {
    if (depth > MAX_DEPTH) throw new CborError('nesting too deep');
    const initial = this.u8();
    const major = initial >> 5;
    const info = initial & 31;
    switch (major) {
      case 0: return toNumber(this.argument(info));
      case 1: return toNumber(-1n - this.argument(info));
      case 2: {
        const n = this.length(info);
        const out = this.buf.slice(this.pos, this.pos + n);
        this.pos += n;
        return out;
      }
      case 3: {
        const n = this.length(info);
        const text = utf8Decoder.decode(this.buf.subarray(this.pos, this.pos + n));
        this.pos += n;
        return text;
      }
      case 4: {
        const n = this.length(info);
        const out = [];
        for (let i = 0; i < n; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        const n = this.length(info);
        const out = Object.create(null);
        for (let i = 0; i < n; i++) {
          const key = this.item(depth + 1);
          if (typeof key !== 'string') throw new CborError('map keys must be text strings');
          if (Object.prototype.hasOwnProperty.call(out, key)) throw new CborError('duplicate map key');
          out[key] = this.item(depth + 1);
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError('floats, undefined and simple values are not allowed');
      default:
        throw new CborError('tags are not allowed');
    }
  }
}

function toNumber(big) {
  return big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(big)
    : big;
}

/**
 * Decode exactly one deterministic CBOR item. Throws CborError on trailing
 * bytes or on any non-canonical encoding (re-encode must be byte-identical).
 */
export function decode(input) {
  if (!(input instanceof Uint8Array)) throw new TypeError('decode expects a Uint8Array');
  const reader = new Reader(input);
  const value = reader.item(0);
  if (reader.pos !== input.length) throw new CborError('trailing bytes after CBOR item');
  if (!equalBytes(encode(value), input)) throw new CborError('input is not deterministically encoded');
  return value;
}
