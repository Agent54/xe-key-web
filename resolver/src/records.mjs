// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Signed name records (Spec §1.7.3). Every rail carries the SAME dCBOR
// bytes; the rail's own signature (ATProto commit, PKARR packet, Nostr
// event) is only a transport check. Authenticity comes from K_pub:
//
//   publisher-doc  ctx "key-web/publisher/v1\0"   "these are my handles"
//   app-record     ctx "key-web/app-record/v1\0"  "my app <slug> is K_app"
//
// signature input = ctx || dCBOR(record without "sigs"), from at least `kt`
// distinct CURRENT keys of K_pub (the key in a K-ED/K-P256 id, or the KEL
// state of a K-SAID id).
//
// Extension used for legitimate key changes (Spec §1.7.8): an app-record MAY
// carry `succ: { from: <old K_app>, kel?: [...], tomb?: {...} }`, the
// succession proof that lets a binding move from the old K_app to the new one.

import { decode, encode } from './cbor.mjs';
import { concat, utf8 } from './encoding.mjs';
import { signWith, verifyWithPubkey } from './crypto.mjs';
import { keyStateFor, KelError, mergeKel } from './kel.mjs';
import { parseKwId } from './ids.mjs';

export const PUBLISHER_TYPE = 'kw-publisher/1';
export const APP_TYPE = 'kw-app/1';
const CTX = {
  [PUBLISHER_TYPE]: utf8.encode('key-web/publisher/v1\0'),
  [APP_TYPE]: utf8.encode('key-web/app-record/v1\0'),
};
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

export class RecordError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RecordError';
    this.code = code;
  }
}

function withoutSigs(record) {
  const { sigs, ...body } = record;
  return body;
}

export function signingInput(record) {
  return concat(CTX[record.t], encode(withoutSigs(record)));
}

function sign(record, keyPairs) {
  const body = withoutSigs(record);
  const input = concat(CTX[body.t], encode(body));
  return encode({ ...body, sigs: keyPairs.map((kp, i) => ({ i, s: signWith(kp, input) })) });
}

/** Build and sign a publisher document. `keyPairs` are K_pub's CURRENT keys. */
export function signPublisherDoc({ pub, seq, rails, kel }, keyPairs) {
  return sign({ t: PUBLISHER_TYPE, pub, kel, seq, rails }, keyPairs);
}

/** Build and sign an app record. */
export function signAppRecord({ pub, slug, app, seq, loc, succ }, keyPairs) {
  return sign({ t: APP_TYPE, pub, slug, app, seq, loc, succ }, keyPairs);
}

function decodeRecord(bytes, expectedType) {
  let record;
  try {
    record = decode(bytes);
  } catch (e) {
    throw new RecordError('RECORD_MALFORMED', `record is not deterministic CBOR: ${e.message}`);
  }
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.t !== expectedType) {
    throw new RecordError('RECORD_MALFORMED', `expected a ${expectedType} record`);
  }
  if (!Number.isSafeInteger(record.seq) || record.seq < 0) {
    throw new RecordError('RECORD_MALFORMED', 'seq must be an unsigned integer');
  }
  if (!Array.isArray(record.sigs) || record.sigs.length === 0) {
    throw new RecordError('RECORD_UNSIGNED', 'record carries no signatures');
  }
  try {
    parseKwId(record.pub);
  } catch (e) {
    throw new RecordError('RECORD_MALFORMED', `pub: ${e.message}`);
  }
  return record;
}

function checkSignatures(record, state) {
  if (state.tombstoned) {
    throw new RecordError('PUBLISHER_RETIRED', `${record.pub} is tombstoned and can no longer sign records`);
  }
  const input = signingInput(record);
  const ok = new Set();
  for (const sig of record.sigs) {
    if (!Number.isInteger(sig?.i) || sig.i < 0 || sig.i >= state.keys.length || ok.has(sig.i)) continue;
    if (verifyWithPubkey(state.keys[sig.i], input, sig.s)) ok.add(sig.i);
  }
  if (ok.size < state.kt) {
    throw new RecordError('BAD_SIGNATURE', `${record.t} is not signed by ${state.kt} current key(s) of ${record.pub}`);
  }
}

/**
 * Verify a publisher document. `knownKel` is the KEL this resolver already
 * holds for that K_pub (it must be a prefix of the document's KEL).
 * Returns { doc, state, kel }.
 */
export function verifyPublisherDoc(bytes, { knownKel, knownKelFor } = {}) {
  const doc = decodeRecord(bytes, PUBLISHER_TYPE);
  if (!doc.rails || typeof doc.rails !== 'object' || Array.isArray(doc.rails)) {
    throw new RecordError('RECORD_MALFORMED', 'rails must be a map');
  }
  let kel;
  let state;
  try {
    kel = parseKwId(doc.pub).type === 'K-SAID'
      ? mergeKel(knownKel ?? knownKelFor?.(doc.pub), doc.kel)
      : undefined;
    state = keyStateFor(doc.pub, kel);
  } catch (e) {
    if (e instanceof KelError) throw new RecordError(e.code, e.message);
    throw e;
  }
  checkSignatures(doc, state);
  return { doc, state, kel };
}

/** Verify an app record against K_pub's current key state. Returns the record. */
export function verifyAppRecord(bytes, publisherState) {
  const rec = decodeRecord(bytes, APP_TYPE);
  if (rec.pub !== publisherState.kwId) {
    throw new RecordError('PUBLISHER_MISMATCH', 'app record and publisher document name different publishers');
  }
  if (typeof rec.slug !== 'string' || !SLUG_RE.test(rec.slug)) {
    throw new RecordError('RECORD_MALFORMED', 'slug must be an LDH label of 1..40 chars');
  }
  try {
    parseKwId(rec.app);
  } catch (e) {
    throw new RecordError('RECORD_MALFORMED', `app: ${e.message}`);
  }
  checkSignatures(rec, publisherState);
  return rec;
}

/** Decode without verifying (for display and debugging only). */
export function inspectRecord(bytes) {
  return decode(bytes);
}
