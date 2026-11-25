// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// KERI pre-rotation (Spec §4) and K_pub-signed records (Spec §1.7.3).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, p256 } from '../src/crypto.mjs';
import { encode, decode } from '../src/cbor.mjs';
import { parseKwId, kwIdForPubkey } from '../src/ids.mjs';
import {
  incept, rotate, tombstone, evaluateKel, mergeKel, successionProven, simpleTombstone, pubkeyOf, eventDigest,
} from '../src/kel.mjs';
import { signPublisherDoc, signAppRecord, verifyPublisherDoc, verifyAppRecord } from '../src/records.mjs';
import { testSeed, makeApp } from '../src/fixtures.mjs';

const key = (label) => ed25519.fromSeed(testSeed(`kel-test/${label}`));
const [k0, k1, k2, thief] = ['k0', 'k1', 'k2', 'thief'].map(key);

function threeEventKel() {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  const kel = [event];
  kel.push(rotate(kel, { revealed: [k1], next: [k2] }));
  return { kwId, kel };
}

test('inception: the kw-id is the self-addressing digest (K-SAID, ...aayc)', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  assert.equal(parseKwId(kwId).type, 'K-SAID');
  assert.ok(kwId.endsWith('aayc'));
  const state = evaluateKel(kwId, [event]);
  assert.deepEqual(state.keys[0].key, k0.publicKey);
  assert.equal(state.kelSn, 0);
  assert.equal(state.next.length, 1, 'only a DIGEST of the next key is published');
  assert.equal(JSON.stringify(Array.from(encode(event.e))).includes(JSON.stringify(Array.from(k1.publicKey))), false);
});

test('rotation to the pre-committed key is accepted; the id never changes', () => {
  const { kwId, kel } = threeEventKel();
  const state = evaluateKel(kwId, kel);
  assert.deepEqual(state.keys[0].key, k1.publicKey);
  assert.equal(state.kelSn, 1);
});

test('a thief holding only the CURRENT key cannot rotate', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  // The thief reveals a key of their own choosing: never pre-committed.
  const forged = rotate([event], { revealed: [thief], next: [thief] });
  assert.throws(() => evaluateKel(kwId, [event, forged]), { code: 'KEL_NOT_PRECOMMITTED' });
  // Revealing the right public key but signing with the current key fails too.
  const e = rotate([event], { revealed: [k1], next: [k2] });
  const resigned = { e: e.e, sigs: [{ i: 0, s: ed25519.sign(k0, new Uint8Array(0)) }] };
  assert.throws(() => evaluateKel(kwId, [event, resigned]), { code: 'KEL_BAD_SIGNATURE' });
});

test('KEL chain, sequence and digest are enforced', () => {
  const { kwId, kel } = threeEventKel();
  const badChain = { ...kel[1], e: { ...kel[1].e, p: new Uint8Array(32) } };
  assert.throws(() => evaluateKel(kwId, [kel[0], badChain]), { code: 'KEL_BAD_CHAIN' });
  const badSn = { ...kel[1], e: { ...kel[1].e, sn: 5 } };
  assert.throws(() => evaluateKel(kwId, [kel[0], badSn]), { code: 'KEL_BAD_SEQUENCE' });
  const other = incept({ current: [k2], next: [k1] });
  assert.throws(() => evaluateKel(kwId, [other.event]), { code: 'KEL_WRONG_ID' });
  const tampered = { ...kel[0], e: { ...kel[0].e, kt: 1, dt: 7 } };
  assert.throws(() => evaluateKel(kwId, [tampered]), { code: 'KEL_BAD_DIGEST' });
});

test('tomb: only the pre-committed NEXT keys may retire an identity', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  const successor = makeApp('successor').id;
  const byCurrent = tombstone([event], { revealed: [k0], successor });
  assert.throws(() => evaluateKel(kwId, [event, byCurrent]), { code: 'KEL_NOT_PRECOMMITTED' });
  const tomb = tombstone([event], { revealed: [k1], successor });
  const state = evaluateKel(kwId, [event, tomb]);
  assert.equal(state.tombstoned, true);
  assert.equal(state.successor, successor);
  const after = rotate([event, tomb], { revealed: [k2], next: [k0] });
  assert.throws(() => evaluateKel(kwId, [event, tomb, after]), { code: 'KEL_AFTER_TOMB' });
});

test('unsupported authority profiles fail closed', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  const rec = { e: { t: 'rec', v: 'kw-kel/1', sn: 1, p: eventDigest(event.e), dt: 0 }, sigs: [] };
  assert.throws(() => evaluateKel(kwId, [event, rec]), { code: 'KEL_UNSUPPORTED' });
});

test('mergeKel: known KEL must be a prefix (duplicity freezes)', () => {
  const { kel } = threeEventKel();
  assert.equal(mergeKel(kel.slice(0, 1), kel), kel);
  assert.equal(mergeKel(kel, kel.slice(0, 1)), kel, 'never shrink to an older view');
  const fork = rotate(kel.slice(0, 1), { revealed: [k1], next: [thief] });
  assert.throws(() => mergeKel(kel, [kel[0], fork]), { code: 'KEL_DUPLICITY' });
});

test('succession proofs: K-SAID tomb and K-ED self-signed tomb', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  const to = makeApp('to').id;
  assert.equal(successionProven(kwId, to, { kel: [event, tombstone([event], { revealed: [k1], successor: to })] }), true);
  assert.equal(successionProven(kwId, makeApp('x').id, { kel: [event, tombstone([event], { revealed: [k1], successor: to })] }), false);
  assert.equal(successionProven(kwId, to, { kel: [event] }), false);
  const edId = kwIdForPubkey(pubkeyOf(k2));
  assert.equal(successionProven(edId, to, { tomb: simpleTombstone(k2, { successor: to }) }), true);
  assert.equal(successionProven(edId, to, { tomb: simpleTombstone(thief, { successor: to }) }), false);
  assert.equal(successionProven(edId, to, undefined), false);
});

test('records: K-ED publisher sign/verify and tamper detection', () => {
  const pub = kwIdForPubkey(pubkeyOf(k0));
  const app = makeApp('records').id;
  const rails = { at: { handle: 'alice.example', did: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa' } };
  const pdocBytes = signPublisherDoc({ pub, seq: 1, rails }, [k0]);
  const { doc, state } = verifyPublisherDoc(pdocBytes);
  assert.equal(doc.rails.at.handle, 'alice.example');
  const recBytes = signAppRecord({ pub, slug: 'cool-site', app, seq: 1 }, [k0]);
  assert.equal(verifyAppRecord(recBytes, state).app, app);

  const forged = signAppRecord({ pub, slug: 'cool-site', app, seq: 1 }, [thief]);
  assert.throws(() => verifyAppRecord(forged, state), { code: 'BAD_SIGNATURE' });
  const flipped = Uint8Array.from(recBytes);
  flipped[flipped.length - 1] ^= 1;
  assert.throws(() => verifyAppRecord(flipped, state), { code: 'BAD_SIGNATURE' });
  const decoded = decode(recBytes);
  const otherPub = signAppRecord({ pub: kwIdForPubkey(pubkeyOf(k1)), slug: 'cool-site', app, seq: 1 }, [k1]);
  assert.throws(() => verifyAppRecord(otherPub, state), { code: 'PUBLISHER_MISMATCH' });
  assert.equal(decoded.t, 'kw-app/1');
  assert.throws(() => verifyPublisherDoc(Uint8Array.of(0xa0)), { code: 'RECORD_MALFORMED' });
});

test('records: K-SAID publisher follows its KEL through rotation', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  const rails = { dht: { pkarr: 'x'.repeat(52) } };
  const app = makeApp('said-records').id;
  const v1 = verifyPublisherDoc(signPublisherDoc({ pub: kwId, seq: 1, rails, kel: [event] }, [k0]));
  assert.equal(verifyAppRecord(signAppRecord({ pub: kwId, slug: 's', app, seq: 1 }, [k0]), v1.state).app, app);

  const kel = [event, rotate([event], { revealed: [k1], next: [k2] })];
  const v2 = verifyPublisherDoc(signPublisherDoc({ pub: kwId, seq: 2, rails, kel }, [k1]), { knownKel: [event] });
  assert.equal(v2.state.kelSn, 1);
  assert.equal(verifyAppRecord(signAppRecord({ pub: kwId, slug: 's', app, seq: 2 }, [k1]), v2.state).app, app);
  // The rotated-out key (e.g. stolen) no longer verifies anything.
  assert.throws(() => verifyAppRecord(signAppRecord({ pub: kwId, slug: 's', app, seq: 3 }, [k0]), v2.state), { code: 'BAD_SIGNATURE' });
  assert.throws(() => verifyPublisherDoc(signPublisherDoc({ pub: kwId, seq: 3, rails, kel }, [k0])), { code: 'BAD_SIGNATURE' });
  // Replaying an OLDER document (older KEL view, old key) against the newer
  // KEL this resolver already holds is rejected: no rollback to the old key.
  assert.throws(
    () => verifyPublisherDoc(signPublisherDoc({ pub: kwId, seq: 1, rails, kel: [event] }, [k0]), { knownKel: kel }),
    { code: 'BAD_SIGNATURE' });
  // A K-SAID publisher document without a KEL is rejected.
  assert.throws(() => verifyPublisherDoc(signPublisherDoc({ pub: kwId, seq: 1, rails }, [k0])), { code: 'KEL_EMPTY' });
});

test('records: K-P256 publishers verify with ECDSA', () => {
  const kp = p256.generate();
  const pub = kwIdForPubkey(pubkeyOf(kp));
  assert.equal(parseKwId(pub).type, 'K-P256');
  const { state } = verifyPublisherDoc(signPublisherDoc({ pub, seq: 1, rails: {} }, [kp]));
  const app = makeApp('p256').id;
  assert.equal(verifyAppRecord(signAppRecord({ pub, slug: 'p', app, seq: 1 }, [kp]), state).app, app);
});

test('KEL threshold rejects duplicate keys in icp and rot', () => {
  const { kwId, event } = incept({ current: [k0], next: [k1, k2], kt: 1, nt: 2 });
  const dupRot = rotate([event], { revealed: [k1, k1], next: [k2] });
  assert.throws(() => evaluateKel(kwId, [event, dupRot]), { code: 'KEL_BAD_EVENT' });
  const dupIcp = incept({ current: [k0, k0], next: [k1], kt: 2, nt: 1 });
  assert.throws(() => evaluateKel(dupIcp.kwId, [dupIcp.event]), { code: 'KEL_BAD_EVENT' });
});
