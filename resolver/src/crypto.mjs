// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Real signatures, no dependencies:
//   * Ed25519 and ECDSA P-256 through node:crypto (raw 32-byte / compressed
//     33-byte public keys, as carried in key-web IDs);
//   * BIP-340 Schnorr over secp256k1 in BigInt arithmetic, because Nostr
//     events are signed that way and node:crypto does not implement it.
//     Verification is used for rail transport checks only; key-web
//     authenticity always comes from the Ed25519/P-256 K_pub signature.

import crypto from 'node:crypto';
import { base64url, bytes, concat, equalBytes } from './encoding.mjs';

export const sha256 = (data) => new Uint8Array(crypto.createHash('sha256').update(bytes(data)).digest());
export const sha512 = (data) => new Uint8Array(crypto.createHash('sha512').update(bytes(data)).digest());
export const randomBytes = (n) => new Uint8Array(crypto.randomBytes(n));

// --- Ed25519 -----------------------------------------------------------------

const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export const ed25519 = {
  /** Deterministic key pair from a 32-byte seed. */
  fromSeed(seed) {
    const s = bytes(seed);
    if (s.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
    const privateKey = crypto.createPrivateKey({
      key: Buffer.from(concat(ED25519_PKCS8_PREFIX, s)),
      format: 'der',
      type: 'pkcs8',
    });
    const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
    return { alg: 'ed25519', seed: s, privateKey, publicKey: base64url.decode(jwk.x) };
  },

  generate() {
    return ed25519.fromSeed(randomBytes(32));
  },

  sign(keyPair, message) {
    return new Uint8Array(crypto.sign(null, Buffer.from(bytes(message)), keyPair.privateKey));
  },

  verify(publicKey, message, signature) {
    const pk = bytes(publicKey);
    const sig = bytes(signature);
    if (pk.length !== 32 || sig.length !== 64) return false;
    try {
      const key = crypto.createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: base64url.encode(pk) },
        format: 'jwk',
      });
      return crypto.verify(null, Buffer.from(bytes(message)), key, Buffer.from(sig));
    } catch {
      return false;
    }
  },
};

// --- ECDSA P-256 (K-P256 identities) ------------------------------------------

function p256Compress(jwk) {
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  return concat(Uint8Array.of(y[31] & 1 ? 0x03 : 0x02), x);
}

export const p256 = {
  generate() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return { alg: 'p256', privateKey, publicKey: p256Compress(publicKey.export({ format: 'jwk' })) };
  },

  sign(keyPair, message) {
    return new Uint8Array(
      crypto.sign('sha256', Buffer.from(bytes(message)), { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' }),
    );
  },

  verify(compressedPublicKey, message, signature) {
    const pk = bytes(compressedPublicKey);
    const sig = bytes(signature);
    if (pk.length !== 33 || sig.length !== 64) return false;
    try {
      const raw = crypto.ECDH.convertKey(Buffer.from(pk), 'prime256v1', undefined, undefined, 'uncompressed');
      const key = crypto.createPublicKey({
        key: {
          kty: 'EC',
          crv: 'P-256',
          x: Buffer.from(raw.subarray(1, 33)).toString('base64url'),
          y: Buffer.from(raw.subarray(33, 65)).toString('base64url'),
        },
        format: 'jwk',
      });
      return crypto.verify('sha256', Buffer.from(bytes(message)), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig));
    } catch {
      return false;
    }
  },
};

/** Verify with a key-web `pubkey` map: { alg: "ed25519" | "p256", key }. */
export function verifyWithPubkey(pubkey, message, signature) {
  if (!pubkey || !(pubkey.key instanceof Uint8Array)) return false;
  if (pubkey.alg === 'ed25519') return ed25519.verify(pubkey.key, message, signature);
  if (pubkey.alg === 'p256') return p256.verify(pubkey.key, message, signature);
  return false;
}

export function signWith(keyPair, message) {
  if (keyPair.alg === 'ed25519') return ed25519.sign(keyPair, message);
  if (keyPair.alg === 'p256') return p256.sign(keyPair, message);
  throw new TypeError(`unknown key algorithm ${keyPair.alg}`);
}

// --- BIP-340 Schnorr over secp256k1 ---------------------------------------------

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

const mod = (a, m = P) => ((a % m) + m) % m;

function powMod(base, exp, m) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

const inv = (a) => powMod(a, P - 2n, P);

function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const lambda = x1 === x2 && y1 === y2
    ? mod(3n * x1 * x1 * inv(2n * y1))
    : mod((y2 - y1) * inv(mod(x2 - x1)));
  const x3 = mod(lambda * lambda - x1 - x2);
  return [x3, mod(lambda * (x1 - x3) - y1)];
}

function pointMul(point, scalar) {
  let result = null;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

const toBig = (b) => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`);
const toBytes32 = (n) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
const hasEvenY = (pt) => (pt[1] & 1n) === 0n;

function liftX(x) {
  if (x >= P) return null;
  const c = mod(x * x * x + 7n);
  const y = powMod(c, (P + 1n) / 4n, P);
  if (mod(y * y) !== c) return null;
  return [x, (y & 1n) === 0n ? y : P - y];
}

function taggedHash(tag, ...parts) {
  const t = sha256(tag);
  return sha256(concat(t, t, ...parts));
}

export const schnorr = {
  publicKey(secretKey) {
    const d = toBig(bytes(secretKey));
    if (d <= 0n || d >= N) throw new RangeError('invalid secp256k1 secret key');
    return toBytes32(pointMul(G, d)[0]);
  },

  sign(message, secretKey, auxRand = new Uint8Array(32)) {
    const m = bytes(message);
    const d0 = toBig(bytes(secretKey));
    if (d0 <= 0n || d0 >= N) throw new RangeError('invalid secp256k1 secret key');
    const Pt = pointMul(G, d0);
    const d = hasEvenY(Pt) ? d0 : N - d0;
    const px = toBytes32(Pt[0]);
    const t = toBytes32(d ^ toBig(taggedHash('BIP0340/aux', bytes(auxRand))));
    const k0 = mod(toBig(taggedHash('BIP0340/nonce', t, px, m)), N);
    if (k0 === 0n) throw new Error('schnorr: nonce is zero');
    const R = pointMul(G, k0);
    const k = hasEvenY(R) ? k0 : N - k0;
    const rx = toBytes32(R[0]);
    const e = mod(toBig(taggedHash('BIP0340/challenge', rx, px, m)), N);
    return concat(rx, toBytes32(mod(k + e * d, N)));
  },

  verify(signature, message, publicKey) {
    const sig = bytes(signature);
    const pk = bytes(publicKey);
    if (sig.length !== 64 || pk.length !== 32) return false;
    const Pt = liftX(toBig(pk));
    if (!Pt) return false;
    const r = toBig(sig.subarray(0, 32));
    const s = toBig(sig.subarray(32, 64));
    if (r >= P || s >= N) return false;
    const e = mod(toBig(taggedHash('BIP0340/challenge', sig.subarray(0, 32), pk, bytes(message))), N);
    const R = pointAdd(pointMul(G, s), pointMul(Pt, N - e));
    if (R === null || !hasEvenY(R)) return false;
    return equalBytes(toBytes32(R[0]), sig.subarray(0, 32));
  },
};
