// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Byte helpers shared by the page, the key-origin loader, the service
// worker and Node. Nothing here touches the DOM or a Node-only API.

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (text) => encoder.encode(text);
export const fromUtf8 = (bytes) => strictDecoder.decode(bytes);

export function concat(parts) {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function compareBytes(a, b) {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

export const sameBytes = (a, b) => a.length === b.length && compareBytes(a, b) === 0;

const HEX = '0123456789abcdef';

export function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 15];
  return out;
}

export function fromHex(text) {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) throw new Error('not lower-case hex');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

/** RFC 4648 base32, lower case, no padding: the alphabet of a Web Bundle ID. */
export function base32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of text) {
    const index = B32.indexOf(ch);
    if (index < 0) throw new Error('not base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  if (value !== 0) throw new Error('base32 has stray bits');
  return Uint8Array.from(out);
}

export function base64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export const base64url = (bytes) => base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * Reads base64 the way a person pastes it: standard or URL-safe alphabet,
 * with or without padding, line breaks anywhere, and an optional data: URL
 * prefix. Throws on anything else.
 */
export function base64Decode(text) {
  if (typeof text !== 'string') throw new Error('not base64');
  let body = text.trim();
  const dataUrl = /^data:[^,]*;base64,/i.exec(body);
  if (dataUrl) body = body.slice(dataUrl[0].length);
  body = body.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (body.length === 0 || !/^[A-Za-z0-9+/]+$/.test(body) || body.length % 4 === 1) throw new Error('not base64');
  const binary = atob(body + '='.repeat((4 - (body.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** x's length as 8 big-endian bytes, then x. */
export function len8(bytes) {
  const lead = new Uint8Array(8);
  new DataView(lead.buffer).setBigUint64(0, BigInt(bytes.length));
  return concat([lead, bytes]);
}

export async function sha256(bytes, subtle = globalThis.crypto.subtle) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

export async function sha256Hex(bytes, subtle) {
  return hex(await sha256(bytes, subtle));
}

export async function sha512(bytes, subtle = globalThis.crypto.subtle) {
  return new Uint8Array(await subtle.digest('SHA-512', bytes));
}
