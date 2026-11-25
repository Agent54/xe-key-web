// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Key Event Log with KERI-style pre-rotation (Spec §4.2-§4.7), the identity
// behind K-SAID kw-ids (`...aayc`).
//
//   icp  establishes current keys `k` (threshold `kt`) and COMMITS to the next
//        keys only as digests `n` (threshold `nt`).
//        kw-id = b32( H256(dCBOR(icp with d = 32 zero bytes)) || 00 03 02 )
//   rot  reveals keys whose digests were committed in the prior `n`; it must be
//        signed by `nt` of those revealed keys, and commits a fresh `n`.
//        A thief holding only the CURRENT key can therefore never rotate.
//   tomb terminal; signed by `nt` revealed NEXT keys (never current keys
//        alone); may name a `successor` kw-id.
//
// Event digest  = H256(dCBOR(e)); each event's `p` is its predecessor's digest.
// pubkey digest = H256(dCBOR({alg, key})).
// Event signatures cover  "key-web/kel-event/v1\0" || dCBOR(e).
//
// Clarifications this module makes where the spec CDDL is silent:
//   * a `tomb` carries the revealed next keys in `k` so its signatures can
//     be checked against the committed digests;
//   * `sigs[].i` indexes the key list the event's authority is checked
//     against (`k` for icp, the revealed `k` for rot/tomb).
// Not implemented (rejected, so validation fails closed): `rec`, `veto`,
// guardians, witnesses, and auth = "guardians-final".

import { encode } from './cbor.mjs';
import { concat, equalBytes, utf8 } from './encoding.mjs';
import { sha256, signWith, verifyWithPubkey } from './crypto.mjs';
import { kwIdFor, kwIdForPubkey, parseKwId } from './ids.mjs';

export const KEL_VERSION = 'kw-kel/1';
const EVENT_CTX = utf8.encode('key-web/kel-event/v1\0');
const ZERO32 = new Uint8Array(32);

export class KelError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'KelError';
    this.code = code;
  }
}

export const pubkeyOf = (keyPair) => ({ alg: keyPair.alg, key: keyPair.publicKey });
export const pubkeyDigest = (pubkey) => sha256(encode({ alg: pubkey.alg, key: pubkey.key }));
export const eventDigest = (e) => sha256(encode(e));
const signingInput = (e) => concat(EVENT_CTX, encode(e));

function signEvent(e, keyPairs) {
  return { e, sigs: keyPairs.map((kp, i) => ({ i, s: signWith(kp, signingInput(e)) })) };
}

/** Create a K-SAID inception. `current` and `next` are key-pair arrays. */
export function incept({ current, next, kt = 1, nt = 1, dt = 0 }) {
  if (!current?.length || !next?.length) throw new KelError('KEL_BAD_EVENT', 'icp needs current and next keys');
  const draft = {
    t: 'icp', v: KEL_VERSION, sn: 0, p: null, dt,
    k: current.map(pubkeyOf), kt,
    n: next.map((kp) => pubkeyDigest(pubkeyOf(kp))), nt,
    auth: 'keys-first',
    d: ZERO32,
  };
  const d = sha256(encode(draft));
  const e = { ...draft, d };
  return { kwId: kwIdFor('K-SAID', d), event: signEvent(e, current) };
}

/** Rotate: `revealed` must be the key pairs committed by the previous `n`. */
export function rotate(kel, { revealed, next, kt = 1, nt = 1, dt = 0 }) {
  const prev = kel[kel.length - 1].e;
  const e = {
    t: 'rot', v: KEL_VERSION, sn: prev.sn + 1, p: eventDigest(prev), dt,
    k: revealed.map(pubkeyOf), kt,
    n: next.map((kp) => pubkeyDigest(pubkeyOf(kp))), nt,
  };
  return signEvent(e, revealed);
}

/** Tombstone, signed by the revealed NEXT keys. */
export function tombstone(kel, { revealed, reason = 'retired', successor, lastGood = null, dt = 0 }) {
  const prev = kel[kel.length - 1].e;
  const e = {
    t: 'tomb', v: KEL_VERSION, sn: prev.sn + 1, p: eventDigest(prev), dt,
    k: revealed.map(pubkeyOf), reason, successor, lastGood,
  };
  return signEvent(e, revealed);
}

function isPubkey(x) {
  return x && (x.alg === 'ed25519' || x.alg === 'p256') && x.key instanceof Uint8Array;
}

function countValid(signed, keys, threshold) {
  const seen = new Set();
  for (const sig of signed.sigs ?? []) {
    if (!Number.isInteger(sig?.i) || sig.i < 0 || sig.i >= keys.length || seen.has(sig.i)) continue;
    if (verifyWithPubkey(keys[sig.i], signingInput(signed.e), sig.s)) seen.add(sig.i);
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) {
    throw new KelError('KEL_BAD_EVENT', `threshold ${threshold} out of range`);
  }
  return seen.size >= threshold;
}

function checkKeyList(list, name) {
  if (!Array.isArray(list) || list.length === 0 || !list.every(isPubkey)) {
    throw new KelError('KEL_BAD_EVENT', `${name} must be a non-empty list of pubkeys`);
  }
  const seen = new Set();
  for (const pk of list) {
    const id = Buffer.from(pubkeyDigest(pk)).toString('hex');
    if (seen.has(id)) {
      throw new KelError('KEL_BAD_EVENT', `${name} must not contain duplicate keys`);
    }
    seen.add(id);
  }
}

function checkDigests(list, name) {
  if (!Array.isArray(list) || list.length === 0 || !list.every((d) => d instanceof Uint8Array && d.length === 32)) {
    throw new KelError('KEL_BAD_EVENT', `${name} must be a non-empty list of 32-byte digests`);
  }
}

/** Every revealed key must match a distinct digest committed in `commitments`. */
function revealedMatchCommitments(revealed, commitments) {
  const used = new Set();
  for (const pk of revealed) {
    const digest = pubkeyDigest(pk);
    const idx = commitments.findIndex((d, i) => !used.has(i) && equalBytes(d, digest));
    if (idx < 0) return false;
    used.add(idx);
  }
  return true;
}

/**
 * Validate a KEL for `kwId` (Spec §4.5) and return the current key state:
 *   { kwId, keys, kt, next, nt, kelSn, tip, tombstoned, successor, lastGood }
 * Throws KelError (fail closed) on any violation.
 */
export function evaluateKel(kwId, kel) {
  const id = parseKwId(kwId);
  if (id.type !== 'K-SAID') throw new KelError('KEL_NOT_SAID', `${kwId} is not a K-SAID identity`);
  if (!Array.isArray(kel) || kel.length === 0) throw new KelError('KEL_EMPTY', 'K-SAID identities need a KEL');

  const icp = kel[0].e;
  if (icp?.t !== 'icp' || icp.v !== KEL_VERSION || icp.sn !== 0 || icp.p !== null) {
    throw new KelError('KEL_BAD_EVENT', 'kel[0] must be an icp with sn 0 and p null');
  }
  if (icp.auth !== 'keys-first') {
    throw new KelError('KEL_UNSUPPORTED', `auth profile ${icp.auth} is not supported by this resolver`);
  }
  if (icp.g !== undefined || icp.w !== undefined) {
    throw new KelError('KEL_UNSUPPORTED', 'guardians and witnesses are not supported by this resolver');
  }
  checkKeyList(icp.k, 'icp.k');
  checkDigests(icp.n, 'icp.n');
  const selfDigest = sha256(encode({ ...icp, d: ZERO32 }));
  if (!(icp.d instanceof Uint8Array) || !equalBytes(icp.d, selfDigest)) {
    throw new KelError('KEL_BAD_DIGEST', 'icp self-digest mismatch');
  }
  if (!equalBytes(id.payload, icp.d)) throw new KelError('KEL_WRONG_ID', 'icp digest does not match the kw-id');
  if (!countValid(kel[0], icp.k, icp.kt)) throw new KelError('KEL_BAD_SIGNATURE', 'icp is not signed by kt current keys');

  const state = {
    kwId, keys: icp.k, kt: icp.kt, next: icp.n, nt: icp.nt,
    kelSn: 0, tip: eventDigest(icp), tombstoned: false, successor: null, lastGood: null,
  };

  for (let i = 1; i < kel.length; i++) {
    const signed = kel[i];
    const e = signed?.e;
    if (state.tombstoned) throw new KelError('KEL_AFTER_TOMB', 'no event may follow a tomb');
    if (!e || e.v !== KEL_VERSION || e.sn !== i) throw new KelError('KEL_BAD_SEQUENCE', `event ${i} has sn ${e?.sn}`);
    if (!(e.p instanceof Uint8Array) || !equalBytes(e.p, state.tip)) {
      throw new KelError('KEL_BAD_CHAIN', `event ${i} does not chain to its predecessor`);
    }
    switch (e.t) {
      case 'rot': {
        checkKeyList(e.k, 'rot.k');
        checkDigests(e.n, 'rot.n');
        if (!revealedMatchCommitments(e.k, state.next)) {
          throw new KelError('KEL_NOT_PRECOMMITTED', `rot ${i} reveals keys that were never pre-committed`);
        }
        if (!countValid(signed, e.k, state.nt)) {
          throw new KelError('KEL_BAD_SIGNATURE', `rot ${i} is not signed by nt pre-committed next keys`);
        }
        Object.assign(state, { keys: e.k, kt: e.kt, next: e.n, nt: e.nt, kelSn: e.sn });
        break;
      }
      case 'tomb': {
        checkKeyList(e.k, 'tomb.k');
        if (!revealedMatchCommitments(e.k, state.next)) {
          throw new KelError('KEL_NOT_PRECOMMITTED', 'tomb must be signed by pre-committed next keys, never current keys alone');
        }
        if (!countValid(signed, e.k, state.nt)) {
          throw new KelError('KEL_BAD_SIGNATURE', 'tomb is not signed by nt next keys');
        }
        if (e.successor !== undefined) parseKwId(e.successor);
        Object.assign(state, {
          tombstoned: true, successor: e.successor ?? null, lastGood: e.lastGood ?? null, kelSn: e.sn,
        });
        break;
      }
      case 'rec':
      case 'veto':
        throw new KelError('KEL_UNSUPPORTED', `${e.t} events (guardian recovery) are not supported by this resolver`);
      default:
        throw new KelError('KEL_BAD_EVENT', `unknown event type ${e.t}`);
    }
    state.tip = eventDigest(e);
  }
  return state;
}

/**
 * Spec §4.5 rule 5: the KEL already held MUST be a prefix of the incoming one.
 * Returns the longer KEL; throws KEL_DUPLICITY on divergence.
 */
export function mergeKel(known, incoming) {
  if (!known?.length) return incoming;
  if (!incoming?.length) return known;
  const n = Math.min(known.length, incoming.length);
  for (let i = 0; i < n; i++) {
    if (!equalBytes(eventDigest(known[i].e), eventDigest(incoming[i].e))) {
      throw new KelError('KEL_DUPLICITY', `two different events at sn ${i}: freezing this identity`);
    }
  }
  return incoming.length >= known.length ? incoming : known;
}

/**
 * Current signing authority for any kw-id:
 *   K-ED / K-P256: the key in the ID itself, threshold 1, kelSn 0.
 *   K-SAID:        derived from the (validated) KEL.
 */
export function keyStateFor(kwId, kel) {
  const id = parseKwId(kwId);
  if (id.type === 'K-SAID') return evaluateKel(kwId, kel);
  return {
    kwId, keys: [id.pubkey], kt: 1, next: [], nt: 0, kelSn: 0,
    tip: ZERO32, tombstoned: false, successor: null, lastGood: null,
  };
}

/** Self-signed K-ED/K-P256 tombstone statement (the documented weak profile). */
export const SIMPLE_TOMB_CTX = utf8.encode('key-web/simple-tomb/v1\0');

export function simpleTombstone(keyPair, { successor, reason = 'retired', lastGood = null }) {
  const e = { t: 'tomb', v: KEL_VERSION, id: kwIdForPubkey(pubkeyOf(keyPair)), successor, reason, lastGood };
  return { e, sigs: [{ i: 0, s: signWith(keyPair, concat(SIMPLE_TOMB_CTX, encode(e))) }] };
}

/**
 * Succession proof (Spec §1.7.8): may the binding move from `fromId` to `toId`?
 *   K-SAID: `proof.kel` validates for `fromId` and ends in a tomb whose
 *           successor is `toId` (signed by pre-committed next keys).
 *   K-ED/K-P256: `proof.tomb` is a tomb statement for `fromId`, naming
 *           `toId`, signed by that key itself.
 * Returns true/false; never throws.
 */
export function successionProven(fromId, toId, proof) {
  try {
    if (!proof) return false;
    const id = parseKwId(fromId);
    if (id.type === 'K-SAID') {
      const state = evaluateKel(fromId, proof.kel);
      return state.tombstoned && state.successor === toId;
    }
    const tomb = proof.tomb;
    if (!tomb?.e || tomb.e.t !== 'tomb' || tomb.e.id !== fromId || tomb.e.successor !== toId) return false;
    const sig = tomb.sigs?.find((s) => s.i === 0);
    return !!sig && verifyWithPubkey(id.pubkey, concat(SIMPLE_TOMB_CTX, encode(tomb.e)), sig.s);
  } catch {
    return false;
  }
}
