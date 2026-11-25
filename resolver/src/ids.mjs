// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// key-web identifiers (Spec §1.2), byte-compatible with Chromium's
// web_package::SignedWebBundleId:  kw-id = b32(payload || type_suffix)
//
//   K-ED    00 01 02  32-byte Ed25519 public key          56 chars, ends "aaic"
//   K-P256  00 02 02  33-byte compressed P-256 key         58 chars
//   K-SAID  00 03 02  32-byte SHA-256 of the KEL inception 56 chars, ends "aayc"
//   proxy   00 00 02  development only: always rejected

import { base32, utf8 } from './encoding.mjs';
import { sha256 } from './crypto.mjs';

export const KW_TYPES = Object.freeze({
  'K-ED': { suffix: [0x00, 0x01, 0x02], payload: 32, alg: 'ed25519' },
  'K-P256': { suffix: [0x00, 0x02, 0x02], payload: 33, alg: 'p256' },
  'K-SAID': { suffix: [0x00, 0x03, 0x02], payload: 32, alg: null },
});

const PROXY_SUFFIX = [0x00, 0x00, 0x02];
export const KW_ID_RE = /^[a-z2-7]{56}$|^[a-z2-7]{58}$/;
export const MIN_PIN_LENGTH = 16;
export const SHARE_PIN_LENGTH = 20;

export class KwIdError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KwIdError';
  }
}

/** Parse a kw-id. Returns { id, type, payload, pubkey? } or throws KwIdError. */
export function parseKwId(id) {
  if (typeof id !== 'string' || !KW_ID_RE.test(id)) {
    throw new KwIdError(`not a kw-id (56/58 lowercase base32 chars): ${String(id).slice(0, 80)}`);
  }
  let decoded;
  try {
    decoded = base32.decode(id);
  } catch (e) {
    throw new KwIdError(`kw-id is not canonical base32: ${e.message}`);
  }
  const suffix = Array.from(decoded.subarray(decoded.length - 3));
  if (suffix.every((b, i) => b === PROXY_SUFFIX[i])) {
    throw new KwIdError('proxy-mode (development) IDs are never valid key-web IDs');
  }
  for (const [type, info] of Object.entries(KW_TYPES)) {
    if (suffix.every((b, i) => b === info.suffix[i]) && decoded.length === info.payload + 3) {
      const payload = decoded.slice(0, info.payload);
      const result = { id, type, payload };
      if (info.alg) result.pubkey = { alg: info.alg, key: payload };
      return result;
    }
  }
  throw new KwIdError(`unknown kw-id type suffix ${suffix.map((b) => b.toString(16).padStart(2, '0')).join(' ')}`);
}

export function isKwId(id) {
  try {
    parseKwId(id);
    return true;
  } catch {
    return false;
  }
}

/** kw-id for a raw public key (`alg` "ed25519" or "p256"), or a K-SAID digest. */
export function kwIdFor(type, payload) {
  const info = KW_TYPES[type];
  if (!info) throw new KwIdError(`unknown kw-id type ${type}`);
  if (!(payload instanceof Uint8Array) || payload.length !== info.payload) {
    throw new KwIdError(`${type} payload must be ${info.payload} bytes`);
  }
  const out = new Uint8Array(payload.length + 3);
  out.set(payload);
  out.set(info.suffix, payload.length);
  return base32.encode(out);
}

export function kwIdForPubkey(pubkey) {
  if (pubkey.alg === 'ed25519') return kwIdFor('K-ED', pubkey.key);
  if (pubkey.alg === 'p256') return kwIdFor('K-P256', pubkey.key);
  throw new KwIdError(`no kw-id type for algorithm ${pubkey.alg}`);
}

/**
 * Spec §1.7.6:  pin = b32( H256( "key-web-pin/v1\0" || kw-id-ascii ) )[0..n]
 * Test vector: mix2p32...aaic -> pin20 "e4g5saaasdl6ahelvnt4".
 */
export function pinFor(kwId, length = SHARE_PIN_LENGTH) {
  parseKwId(kwId);
  if (!Number.isInteger(length) || length < MIN_PIN_LENGTH || length > 52) {
    throw new KwIdError(`pin length must be between ${MIN_PIN_LENGTH} and 52`);
  }
  return base32.encode(sha256(new Uint8Array([...utf8.encode('key-web-pin/v1\0'), ...utf8.encode(kwId)]))).slice(0, length);
}

/** Constant-time-ish pin comparison; the pin must be at least 16 chars. */
export function pinMatches(pin, kwId) {
  if (typeof pin !== 'string' || pin.length < MIN_PIN_LENGTH || !/^[a-z2-7]+$/.test(pin)) return false;
  const full = pinFor(kwId, 52);
  let diff = 0;
  for (let i = 0; i < pin.length; i++) diff |= pin.charCodeAt(i) ^ full.charCodeAt(i);
  return diff === 0;
}

/** "mix2p32o…aaic": first 8 and last 4 characters (Spec §4.8 rule 3). */
export function fingerprint(kwId) {
  return `${kwId.slice(0, 8)}…${kwId.slice(-4)}`;
}
