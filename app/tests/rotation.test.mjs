// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Key rotation with a pre-committed next key.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64url } from '../runner/src/engine/bytes.js';
import { ROTATION_FORMAT, ROTATION_STEPS, keyDigest, verifyRotation } from '../runner/src/engine/rotation.js';
import { makeRotation, rawPublicKey, webBundleId } from '../scripts/lib/swbn.mjs';
import { newKey } from './helpers.mjs';

const ISSUED = '2026-01-01T00:00:00.000Z';

async function world() {
  const current = newKey();
  const next = newKey();
  const attacker = newKey();
  const currentId = webBundleId(rawPublicKey(current));
  const committedDigest = await keyDigest(rawPublicKey(next));
  const honest = { fromId: currentId, toPublicKey: rawPublicKey(next), sequence: 1, issued: ISSUED };
  return { current, next, attacker, currentId, committedDigest, honest, trust: { currentId, committedDigest, currentSequence: 0 } };
}

describe('a rotation certificate', () => {
  test('is accepted when the old key signed it, the new key was committed to, and the new key signed too', async () => {
    const w = await world();
    const report = await verifyRotation(makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next }), w.trust);
    assert.equal(report.ok, true);
    assert.equal(report.code, 'ROTATION_ACCEPTED');
    assert.equal(report.from, w.currentId);
    assert.equal(report.to, webBundleId(rawPublicKey(w.next)));
    assert.equal(report.sequence, 1);
    assert.deepEqual(report.steps.map((step) => step.id), ROTATION_STEPS.map(([id]) => id));
    assert.ok(report.steps.every((step) => step.ok === true));
  });

  test('is rejected unsigned', async () => {
    const w = await world();
    const none = await verifyRotation(makeRotation({ ...w.honest, signFrom: null, signTo: null }), w.trust);
    assert.equal(none.code, 'ROTATION_UNSIGNED');
    assert.equal(none.to, null);
    assert.equal((await verifyRotation(makeRotation({ ...w.honest, signFrom: w.current, signTo: null }), w.trust)).code, 'ROTATION_UNSIGNED');
    assert.equal((await verifyRotation(makeRotation({ ...w.honest, signFrom: null, signTo: w.next }), w.trust)).code, 'ROTATION_UNSIGNED');
  });

  test('is rejected when a stranger signs as the old key', async () => {
    const w = await world();
    const forged = makeRotation({ fromId: w.currentId, toPublicKey: rawPublicKey(w.attacker), sequence: 1, issued: ISSUED, signFrom: w.attacker, signTo: w.attacker });
    assert.equal((await verifyRotation(forged, w.trust)).code, 'ROTATION_SIGNATURE_INVALID');
    // Even pointing at the committed key does not help a stranger.
    const sneaky = makeRotation({ ...w.honest, signFrom: w.attacker, signTo: w.next });
    assert.equal((await verifyRotation(sneaky, w.trust)).code, 'ROTATION_SIGNATURE_INVALID');
  });

  test('is rejected when the stolen old key points the origin at a key that was never committed to', async () => {
    const w = await world();
    const stolen = makeRotation({ fromId: w.currentId, toPublicKey: rawPublicKey(w.attacker), sequence: 1, issued: ISSUED, signFrom: w.current, signTo: w.attacker });
    const report = await verifyRotation(stolen, w.trust);
    assert.equal(report.code, 'PRECOMMIT_MISMATCH');
    assert.equal(report.steps.find((step) => step.id === 'signature-from').ok, true);
    assert.equal(report.ok, false);
  });

  test('is rejected when there was no commitment at all', async () => {
    const w = await world();
    const report = await verifyRotation(makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next }), { ...w.trust, committedDigest: null });
    assert.equal(report.code, 'PRECOMMIT_MISSING');
  });

  test('is rejected without proof that the new key agreed', async () => {
    const w = await world();
    const report = await verifyRotation(makeRotation({ ...w.honest, signFrom: w.current, signTo: w.attacker }), w.trust);
    assert.equal(report.code, 'ROTATION_POP_INVALID');
    // The two signatures are not interchangeable: each covers its own role.
    const good = makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next });
    const swapped = { ...good, signature_from: good.signature_to, signature_to: good.signature_from };
    assert.equal((await verifyRotation(swapped, w.trust)).code, 'ROTATION_SIGNATURE_INVALID');
  });

  test('cannot be replayed or skipped ahead', async () => {
    const w = await world();
    const good = makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next });
    assert.equal((await verifyRotation(good, { ...w.trust, currentSequence: 1 })).code, 'ROTATION_REPLAY');
    const ahead = makeRotation({ ...w.honest, sequence: 3, signFrom: w.current, signTo: w.next });
    assert.equal((await verifyRotation(ahead, w.trust)).code, 'ROTATION_REPLAY');
  });

  test('is rejected for another origin', async () => {
    const w = await world();
    const good = makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next });
    const elsewhere = webBundleId(rawPublicKey(newKey()));
    assert.equal((await verifyRotation(good, { ...w.trust, currentId: elsewhere })).code, 'ROTATION_WRONG_KEY');
  });

  test('is rejected when a single character of the payload changes after signing', async () => {
    const w = await world();
    const good = makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next });
    const edited = { ...good, payload: good.payload.replace('"sequence":1', '"sequence":1 ') };
    assert.equal((await verifyRotation(edited, w.trust)).code, 'ROTATION_SIGNATURE_INVALID');
    const retargeted = { ...good, payload: good.payload.replace(base64url(rawPublicKey(w.next)), base64url(rawPublicKey(w.attacker))) };
    assert.notEqual((await verifyRotation(retargeted, w.trust)).ok, true);
  });

  test('is rejected when malformed, without throwing', async () => {
    const w = await world();
    const good = makeRotation({ ...w.honest, signFrom: w.current, signTo: w.next });
    const payload = JSON.parse(good.payload);
    const withPayload = (change) => ({ ...good, payload: JSON.stringify({ ...payload, ...change }) });
    const cases = [
      null, 'text', [], {}, { ...good, format: 'key-web-rotation/2' }, { ...good, payload: 12 }, { ...good, payload: '{' }, { ...good, payload: 'null' },
      { ...good, signature_from: 'AAAA' }, { ...good, signature_to: '!!!' },
      withPayload({ to: payload.from }), withPayload({ sequence: 0 }), withPayload({ sequence: '1' }), withPayload({ to_key: 'AAAA' }),
      withPayload({ to: webBundleId(rawPublicKey(newKey())) }), withPayload({ next_key_digest: 'md5:abc' }), withPayload({ from: 'short' }),
    ];
    for (const certificate of cases) {
      const report = await verifyRotation(certificate, w.trust);
      assert.equal(report.ok, false);
      assert.equal(report.code, 'ROTATION_MALFORMED', JSON.stringify(certificate).slice(0, 80));
      assert.equal(report.to, null);
    }
    assert.equal(good.format, ROTATION_FORMAT);
  });

  test('chains: the new key commits to the one after it', async () => {
    const w = await world();
    const third = newKey();
    const thirdDigest = await keyDigest(rawPublicKey(third));
    const first = await verifyRotation(makeRotation({ ...w.honest, nextKeyDigest: thirdDigest, signFrom: w.current, signTo: w.next }), w.trust);
    assert.equal(first.ok, true);
    assert.equal(first.nextKeyDigest, thirdDigest);
    const second = makeRotation({ fromId: first.to, toPublicKey: rawPublicKey(third), sequence: 2, issued: ISSUED, signFrom: w.next, signTo: third });
    const report = await verifyRotation(second, { currentId: first.to, committedDigest: first.nextKeyDigest, currentSequence: first.sequence });
    assert.equal(report.ok, true);
    assert.equal(report.sequence, 2);
  });
});
