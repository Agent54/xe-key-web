// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Byte encodings used by key-web: RFC 4648 base32 (lowercase, unpadded; the
// SignedWebBundleId alphabet), z-base32 (PKARR keys), base64url, hex and
// bech32 (Nostr NIP-19). No dependencies.

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

export const utf8 = new TextEncoder();
export const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export function bytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === 'string') return utf8.encode(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  throw new TypeError('expected bytes');
}

export function concat(...parts) {
  const arrays = parts.map(bytes);
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

export function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function encodeBase32With(alphabet, data) {
  const b = bytes(data);
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of b) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function decodeBase32With(alphabet, name, text) {
  if (typeof text !== 'string') throw new TypeError(`${name}: expected a string`);
  const out = [];
  let value = 0;
  let bits = 0;
  for (const ch of text) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new SyntaxError(`${name}: invalid character ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  // Canonical form only: leftover bits must be zero padding (< 5 bits).
  if (bits >= 5 || value !== 0) throw new SyntaxError(`${name}: non-canonical trailing bits`);
  return Uint8Array.from(out);
}

/** RFC 4648 base32, lowercase, no padding (SignedWebBundleId encoding). */
export const base32 = {
  encode: (data) => encodeBase32With(B32, data),
  decode: (text) => decodeBase32With(B32, 'base32', text),
};

/** z-base32 (as used by PKARR public keys). */
export const zbase32 = {
  encode: (data) => encodeBase32With(ZB32, data),
  decode: (text) => decodeBase32With(ZB32, 'z-base32', text),
};

export const base64url = {
  encode: (data) => Buffer.from(bytes(data)).toString('base64url'),
  decode(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
      throw new SyntaxError('base64url: invalid input');
    }
    return new Uint8Array(Buffer.from(text, 'base64url'));
  },
};

/** Standard base64 (ATProto `$bytes` uses it without padding). */
export const base64 = {
  encode: (data) => Buffer.from(bytes(data)).toString('base64').replace(/=+$/, ''),
  decode(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
      throw new SyntaxError('base64: invalid input');
    }
    return new Uint8Array(Buffer.from(text, 'base64'));
  },
};

export const hex = {
  encode: (data) => Buffer.from(bytes(data)).toString('hex'),
  decode(text) {
    if (typeof text !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(text)) {
      throw new SyntaxError('hex: invalid input');
    }
    return new Uint8Array(Buffer.from(text, 'hex'));
  },
};

// --- bech32 (BIP-173), used by Nostr NIP-19 `npub` ---------------------------

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >>> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >> from) throw new SyntaxError('bech32: bad value');
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new SyntaxError('bech32: non-zero padding');
  }
  return out;
}

export const bech32 = {
  encode(hrp, data) {
    const words = convertBits(bytes(data), 8, 5, true);
    const values = [...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0];
    const mod = polymod(values) ^ 1;
    const checksum = [];
    for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
    return `${hrp}1${[...words, ...checksum].map((w) => BECH32[w]).join('')}`;
  },
  decode(text) {
    if (typeof text !== 'string' || text.length > 90 || text !== text.toLowerCase()) {
      throw new SyntaxError('bech32: invalid string');
    }
    const sep = text.lastIndexOf('1');
    if (sep < 1 || sep + 7 > text.length) throw new SyntaxError('bech32: bad separator');
    const hrp = text.slice(0, sep);
    const values = [];
    for (const c of text.slice(sep + 1)) {
      const v = BECH32.indexOf(c);
      if (v < 0) throw new SyntaxError('bech32: invalid character');
      values.push(v);
    }
    if (polymod([...hrpExpand(hrp), ...values]) !== 1) throw new SyntaxError('bech32: bad checksum');
    return { hrp, data: Uint8Array.from(convertBits(values.slice(0, -6), 5, 8, false)) };
  },
};
