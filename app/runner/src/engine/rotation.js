// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Key rotation with a pre-committed next key, after KERI's pre-rotation.
//
// A bundle signed by the current key carries, in its signed descriptor, the
// SHA-256 of the key that is allowed to come next. That next key has never
// signed anything and never been online. A rotation certificate then has to
// pass three independent tests:
//
//   1. the outgoing key signed it                       (it is not a stranger's)
//   2. the incoming key hashes to the committed digest  (a thief of the
//      outgoing key cannot point the origin at a key of their own)
//   3. the incoming key signed it too                   (whoever holds it agreed)
//
// The certificate is JSON so it can travel by any transport, like a bundle:
//
//   { "format": "key-web-rotation/1",
//     "payload": "<JSON text: from, to, to_key, sequence, next_key_digest, issued>",
//     "signature_from": "<base64url Ed25519>", "signature_to": "<base64url Ed25519>" }
//
// Each signature covers utf8("key-web-rotation/1\n" + role + "\n" + payload),
// where role is "from" or "to". The payload is signed as the exact text it
// arrived as, so there is no canonical-JSON question to get wrong.

import { base64Decode, hex, sha256, utf8 } from './bytes.js';
import { ID_PATTERN, idFromKey, keyFromId, verifyDetached } from './swbn.js';

export const ROTATION_FORMAT = 'key-web-rotation/1';

export const ROTATION_STEPS = Object.freeze([
  ['shape', 'Certificate is well formed', 'ROTATION_MALFORMED'],
  ['signed', 'Carries both signatures', 'ROTATION_UNSIGNED'],
  ['payload', 'Payload names a key, a successor and a sequence', 'ROTATION_MALFORMED'],
  ['from', 'Issued for the key being rotated', 'ROTATION_WRONG_KEY'],
  ['signature-from', 'Ed25519 signature by the outgoing key', 'ROTATION_SIGNATURE_INVALID'],
  ['pre-commitment', 'Incoming key matches the pre-committed digest', 'PRECOMMIT_MISMATCH'],
  ['signature-to', 'Ed25519 proof of possession by the incoming key', 'ROTATION_POP_INVALID'],
  ['sequence', 'Sequence follows the last accepted rotation', 'ROTATION_REPLAY'],
]);

export const ROTATION_FAILURE_TEXT = Object.freeze({
  ROTATION_MALFORMED: 'the certificate is malformed',
  ROTATION_UNSIGNED: 'the certificate is not signed',
  ROTATION_WRONG_KEY: 'the certificate is for a different key',
  ROTATION_SIGNATURE_INVALID: 'the outgoing key did not sign this certificate',
  PRECOMMIT_MISSING: 'the installed bundle committed to no next key, so it cannot be rotated',
  PRECOMMIT_MISMATCH: 'the incoming key is not the one that was committed to in advance',
  ROTATION_POP_INVALID: 'the incoming key did not sign this certificate',
  ROTATION_REPLAY: 'the sequence number does not follow the last accepted rotation',
});

/** The bytes a rotation signature covers. */
export const rotationMessage = (role, payload) => utf8(`${ROTATION_FORMAT}\n${role}\n${payload}`);

export async function keyDigest(rawKey, subtle) {
  return `sha256:${hex(await sha256(rawKey, subtle))}`;
}

class Fail extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function signatureBytes(value) {
  try {
    const bytes = base64Decode(value);
    return bytes.length === 64 ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Checks a rotation certificate against what is already trusted:
 *   currentId        the key origin being rotated
 *   committedDigest  next_key_digest from that origin's verified, signed descriptor
 *   currentSequence  the sequence of the last accepted rotation (0 if none)
 *
 * Never throws for bad input. Resolves with {ok, code, message, steps, from,
 * to, toKey, sequence, nextKeyDigest}.
 */
export async function verifyRotation(certificate, { currentId, committedDigest = null, currentSequence = 0, subtle = globalThis.crypto.subtle } = {}) {
  const report = {
    ok: false, code: null, message: null,
    steps: ROTATION_STEPS.map(([id, label]) => ({ id, label, ok: null, detail: '' })),
    from: null, to: null, toKey: null, sequence: null, nextKeyDigest: null,
  };
  const step = (id) => report.steps.find((entry) => entry.id === id);
  const pass = (id, detail = '') => Object.assign(step(id), { ok: true, detail });
  let current = 'shape';

  try {
    if (certificate === null || typeof certificate !== 'object' || Array.isArray(certificate)) throw new Fail('ROTATION_MALFORMED', 'not a JSON object');
    if (certificate.format !== ROTATION_FORMAT) throw new Fail('ROTATION_MALFORMED', `format is not ${ROTATION_FORMAT}`);
    if (typeof certificate.payload !== 'string' || certificate.payload.length > 4096) throw new Fail('ROTATION_MALFORMED', 'the payload is missing');
    pass('shape', ROTATION_FORMAT);

    current = 'signed';
    if (certificate.signature_from === undefined || certificate.signature_from === null || certificate.signature_from === '') throw new Fail('ROTATION_UNSIGNED', 'there is no signature by the outgoing key');
    if (certificate.signature_to === undefined || certificate.signature_to === null || certificate.signature_to === '') throw new Fail('ROTATION_UNSIGNED', 'there is no signature by the incoming key');
    const signatureFrom = signatureBytes(certificate.signature_from);
    const signatureTo = signatureBytes(certificate.signature_to);
    if (!signatureFrom || !signatureTo) throw new Fail('ROTATION_MALFORMED', 'a signature is not 64 bytes of base64url');
    pass('signed', 'two 64-byte signatures');

    current = 'payload';
    let payload;
    try {
      payload = JSON.parse(certificate.payload);
    } catch {
      throw new Fail('ROTATION_MALFORMED', 'the payload is not JSON');
    }
    if (payload === null || typeof payload !== 'object') throw new Fail('ROTATION_MALFORMED', 'the payload is not an object');
    const { from, to, sequence } = payload;
    if (typeof from !== 'string' || !ID_PATTERN.test(from) || typeof to !== 'string' || !ID_PATTERN.test(to) || from === to) throw new Fail('ROTATION_MALFORMED', 'from and to must be two different key IDs');
    if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Fail('ROTATION_MALFORMED', 'sequence must be a positive integer');
    let toKey;
    let fromKey;
    try {
      toKey = base64Decode(payload.to_key);
      fromKey = keyFromId(from);
      if (toKey.length !== 32 || idFromKey(toKey) !== to) throw new Error('mismatch');
    } catch {
      throw new Fail('ROTATION_MALFORMED', 'to_key is not the key that the successor ID is derived from');
    }
    const next = payload.next_key_digest === null || payload.next_key_digest === undefined ? null : payload.next_key_digest;
    if (next !== null && (typeof next !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(next))) throw new Fail('ROTATION_MALFORMED', 'next_key_digest is not a SHA-256 digest');
    pass('payload', `sequence ${sequence}`);

    current = 'from';
    if (from !== currentId) throw new Fail('ROTATION_WRONG_KEY', 'the certificate rotates a key other than this origin');
    pass('from', 'this origin');

    current = 'signature-from';
    if (!(await verifyDetached(fromKey, signatureFrom, rotationMessage('from', certificate.payload), subtle))) {
      throw new Fail('ROTATION_SIGNATURE_INVALID', 'the signature does not verify under the key this origin is derived from');
    }
    pass('signature-from', 'valid');

    current = 'pre-commitment';
    if (typeof committedDigest !== 'string') throw new Fail('PRECOMMIT_MISSING', 'the installed bundle carries no next_key_digest');
    const actual = await keyDigest(toKey, subtle);
    if (actual !== committedDigest) throw new Fail('PRECOMMIT_MISMATCH', `committed ${committedDigest.slice(0, 23)}…, certificate offers ${actual.slice(0, 23)}…`);
    pass('pre-commitment', `${actual.slice(0, 23)}…`);

    current = 'signature-to';
    if (!(await verifyDetached(toKey, signatureTo, rotationMessage('to', certificate.payload), subtle))) {
      throw new Fail('ROTATION_POP_INVALID', 'the signature does not verify under the incoming key');
    }
    pass('signature-to', 'valid');

    current = 'sequence';
    if (sequence !== currentSequence + 1) throw new Fail('ROTATION_REPLAY', `expected sequence ${currentSequence + 1}, got ${sequence}`);
    pass('sequence', `${currentSequence} → ${sequence}`);

    Object.assign(report, { ok: true, code: 'ROTATION_ACCEPTED', message: 'rotation accepted: the outgoing key handed this origin to the key it committed to in advance', from, to, toKey, sequence, nextKeyDigest: next });
  } catch (error) {
    report.ok = false;
    report.code = error instanceof Fail ? error.code : ROTATION_STEPS.find(([id]) => id === current)[2];
    report.message = `${ROTATION_FAILURE_TEXT[report.code] || 'the rotation was rejected'} (${error.message})`;
    Object.assign(step(current), { ok: false, detail: error.message });
  }
  return report;
}
