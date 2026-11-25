// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The small, strict CBOR subset that Web Bundles and integrity blocks use:
// non-negative integers, byte strings, text strings, arrays and maps, all
// with definite lengths and shortest-form heads. Anything else is an error,
// so there is exactly one byte sequence for each value.

import { compareBytes, concat, fromUtf8, utf8 } from './bytes.js';

/** A CBOR map, kept as entries so keys can be byte strings as well as text. */
export class CborMap {
  constructor(entries = []) {
    this.entries = entries;
  }

  get(key) {
    for (const [k, v] of this.entries) if (k === key) return v;
    return undefined;
  }
}

export function head(major, value) {
  const n = BigInt(value);
  const type = major << 5;
  if (n < 24n) return Uint8Array.of(type | Number(n));
  if (n < 0x100n) return Uint8Array.of(type | 24, Number(n));
  if (n < 0x10000n) return Uint8Array.of(type | 25, Number(n >> 8n), Number(n & 0xffn));
  if (n < 0x100000000n) {
    const out = new Uint8Array(5);
    out[0] = type | 26;
    new DataView(out.buffer).setUint32(1, Number(n));
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = type | 27;
  new DataView(out.buffer).setBigUint64(1, n);
  return out;
}

/** Deterministic CBOR: definite lengths, shortest heads, map keys sorted by length then bytes. */
export function encode(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('cbor: only non-negative integers');
    return head(0, value);
  }
  if (typeof value === 'string') {
    const bytes = utf8(value);
    return concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return concat([head(2, value.length), value]);
  if (Array.isArray(value)) return concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof CborMap) {
    const pairs = value.entries.map(([k, v]) => [encode(k), v]).sort((a, b) => compareBytes(a[0], b[0]));
    for (let i = 1; i < pairs.length; i++) if (compareBytes(pairs[i - 1][0], pairs[i][0]) === 0) throw new Error('cbor: duplicate map key');
    return concat([head(5, pairs.length), ...pairs.flatMap(([k, v]) => [k, encode(v)])]);
  }
  throw new Error('cbor: unsupported value');
}

const LEAST = [24, 0x100, 0x10000, 0x100000000];

/** Strict decoder for the same subset. Returns {value, end}. Byte strings are views, not copies. */
export function decode(bytes, start = 0, depth = 0) {
  if (depth > 16) throw new Error('cbor: nested too deep');
  if (start >= bytes.length) throw new Error('cbor: ran out of bytes');
  const first = bytes[start];
  const major = first >> 5;
  const info = first & 31;
  let offset = start + 1;
  let n;
  if (info < 24) n = info;
  else if (info <= 27) {
    const size = 1 << (info - 24);
    if (offset + size > bytes.length) throw new Error('cbor: ran out of bytes');
    let big = 0n;
    for (let i = 0; i < size; i++) big = (big << 8n) | BigInt(bytes[offset + i]);
    offset += size;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer too large');
    n = Number(big);
    if (n < LEAST[info - 24]) throw new Error('cbor: integer not in its shortest form');
  } else throw new Error('cbor: indefinite lengths and reserved values are not allowed');

  if (major === 0) return { value: n, end: offset };
  if (major === 2 || major === 3) {
    if (offset + n > bytes.length) throw new Error('cbor: string runs past the end');
    const slice = bytes.subarray(offset, offset + n);
    return { value: major === 2 ? slice : fromUtf8(slice), end: offset + n };
  }
  if (major === 4 || major === 5) {
    // Every item takes at least one byte, so a count beyond what is left is a lie.
    if (n > bytes.length - offset) throw new Error('cbor: more items than bytes');
    if (major === 4) {
      const items = [];
      for (let i = 0; i < n; i++) {
        const item = decode(bytes, offset, depth + 1);
        items.push(item.value);
        offset = item.end;
      }
      return { value: items, end: offset };
    }
    const entries = [];
    for (let i = 0; i < n; i++) {
      const key = decode(bytes, offset, depth + 1);
      const value = decode(bytes, key.end, depth + 1);
      entries.push([key.value, value.value]);
      offset = value.end;
    }
    return { value: new CborMap(entries), end: offset };
  }
  throw new Error('cbor: unsupported type');
}
