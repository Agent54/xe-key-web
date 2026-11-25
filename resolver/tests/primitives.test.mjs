// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Encodings, deterministic CBOR and signature primitives.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32, zbase32, base64url, base64, bech32, hex, utf8 } from '../src/encoding.mjs';
import { encode, decode, CborError } from '../src/cbor.mjs';
import { ed25519, p256, schnorr, sha256 } from '../src/crypto.mjs';

test('base32: RFC 4648 lowercase, unpadded, canonical only', () => {
  assert.equal(base32.encode(utf8.encode('foobar')), 'mzxw6ytboi');
  assert.deepEqual(base32.decode('mzxw6ytboi'), utf8.encode('foobar'));
  assert.throws(() => base32.decode('MZXW6YTBOI'), /invalid character/);
  assert.throws(() => base32.decode('mzxw6ytboj'), /non-canonical/); // non-zero padding bits
  for (let n = 0; n < 40; n++) {
    const b = sha256(String(n)).slice(0, n % 33);
    assert.deepEqual(base32.decode(base32.encode(b)), b);
  }
});

test('z-base32 round-trips 32-byte PKARR keys into 52 chars', () => {
  const key = sha256('pkarr');
  const z = zbase32.encode(key);
  assert.equal(z.length, 52);
  assert.match(z, /^[ybndrfg8ejkmcpqxot1uwisza345h769]+$/);
  assert.deepEqual(zbase32.decode(z), key);
});

test('base64url / base64 / hex reject malformed input', () => {
  assert.throws(() => base64url.decode('a+b'), SyntaxError);
  assert.throws(() => base64.decode('a_b'), SyntaxError);
  assert.throws(() => hex.decode('abc'), SyntaxError);
  assert.deepEqual(base64.decode(base64.encode(Uint8Array.of(1, 2, 3, 4))), Uint8Array.of(1, 2, 3, 4));
});

test('bech32 (NIP-19) round-trips and detects corruption', () => {
  const key = sha256('npub');
  const npub = bech32.encode('npub', key);
  assert.equal(npub.length, 63, 'an npub fits exactly one DNS label');
  assert.deepEqual(bech32.decode(npub), { hrp: 'npub', data: key });
  const corrupted = npub.slice(0, -1) + (npub.endsWith('q') ? 'p' : 'q');
  assert.throws(() => bech32.decode(corrupted), /checksum/);
});

test('dCBOR: deterministic map order and shortest integers', () => {
  // Keys sort by encoded bytes: shorter text first, then bytewise.
  assert.equal(hex.encode(encode({ seq: 1, t: 'x', aa: 2 })), 'a36174617862616102637365710' + '1');
  assert.equal(hex.encode(encode(23)), '17');
  assert.equal(hex.encode(encode(24)), '1818');
  assert.equal(hex.encode(encode(-1)), '20');
  assert.equal(hex.encode(encode(2n ** 64n - 1n)), '1bffffffffffffffff');
  const v = { a: [1, -2, 'x', Uint8Array.of(9), null, true, false], b: { c: 300 } };
  assert.deepEqual({ ...decode(encode(v)), b: { ...decode(encode(v)).b } }, v);
});

test('dCBOR decode is strict', () => {
  assert.throws(() => decode(hex.decode('1817')), CborError, 'non-shortest integer');
  assert.throws(() => decode(hex.decode('a2616201616101')), CborError, 'unsorted map');
  assert.throws(() => decode(hex.decode('a2616101616102')), CborError, 'duplicate key');
  assert.throws(() => decode(hex.decode('f93c00')), CborError, 'float');
  assert.throws(() => decode(hex.decode('c240')), CborError, 'tag');
  assert.throws(() => decode(hex.decode('9fff')), CborError, 'indefinite length');
  assert.throws(() => decode(hex.decode('0000')), CborError, 'trailing bytes');
  assert.throws(() => decode(hex.decode('5a7fffffff')), CborError, 'length past end');
  assert.throws(() => encode(1.5), CborError);
});

test('Ed25519: RFC 8032 test 1', () => {
  const kp = ed25519.fromSeed(hex.decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
  assert.equal(hex.encode(kp.publicKey), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  const sig = ed25519.sign(kp, new Uint8Array(0));
  assert.equal(hex.encode(sig),
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  assert.equal(ed25519.verify(kp.publicKey, new Uint8Array(0), sig), true);
  assert.equal(ed25519.verify(kp.publicKey, Uint8Array.of(0), sig), false);
  assert.equal(ed25519.verify(kp.publicKey.slice(1), new Uint8Array(0), sig), false);
});

test('ECDSA P-256 with compressed keys (K-P256)', () => {
  const kp = p256.generate();
  assert.equal(kp.publicKey.length, 33);
  const sig = p256.sign(kp, 'msg');
  assert.equal(p256.verify(kp.publicKey, 'msg', sig), true);
  assert.equal(p256.verify(kp.publicKey, 'msh', sig), false);
  assert.equal(p256.verify(Uint8Array.of(2, ...new Uint8Array(32)), 'msg', sig), false);
});

test('BIP-340 Schnorr: official test vector 0 and tamper detection', () => {
  const sk = hex.decode('0000000000000000000000000000000000000000000000000000000000000003');
  const pk = schnorr.publicKey(sk);
  assert.equal(hex.encode(pk).toUpperCase(), 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
  const msg = new Uint8Array(32);
  const sig = schnorr.sign(msg, sk, new Uint8Array(32));
  assert.equal(hex.encode(sig).toUpperCase(),
    'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0');
  assert.equal(schnorr.verify(sig, msg, pk), true);
  const bad = Uint8Array.from(sig);
  bad[63] ^= 1;
  assert.equal(schnorr.verify(bad, msg, pk), false);
  assert.equal(schnorr.verify(sig, Uint8Array.of(1, ...new Uint8Array(31)), pk), false);
});
