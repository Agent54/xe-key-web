// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Human-readable key-web addresses.
//
//   key-web://<app>.<publisher>.at/     a name looked up on the ATProto handle rail
//   key-web://<app>.<publisher>.dht/    the same kind of name, looked up on the DHT rail
//   key-web://<petname>.local/          a name from your own petname book: no network
//   key-web://<key ID>.key/             no name at all: the address is the key
//
// A rail is only a way to find out which key a name means. It is never
// trusted for that. What a rail returns is a record, signed by the
// publisher's key, saying "this app of mine is this key". The record is
// checked here, and then the runner compares the key with the one it pinned
// the first time the name was used. The rail can go away, or lie, and a
// pinned name still means the key it meant before.
//
//   { "format": "key-web-name/1",
//     "payload": "<JSON text: app, publisher, rail, key, sequence, issued>",
//     "publisher_key": "<base64url Ed25519 public key>",
//     "signature": "<base64url Ed25519 over utf8('key-web-name/1\n' + payload)>",
//     "rotation": [ <rotation certificates, if the key has changed> ] }

import { base32, base64Decode, sha256, utf8 } from './bytes.js';
import { ID_PATTERN, idFromKey, isKeyId, verifyDetached } from './swbn.js';

export const NAME_FORMAT = 'key-web-name/1';

/** The rails, by the last label of an address. Only `at` and `dht` ask the network anything. */
export const RAILS = Object.freeze({
  at: Object.freeze({ suffix: '.at', title: 'ATProto handle rail (simulated)', network: true }),
  dht: Object.freeze({ suffix: '.dht', title: 'PKARR / Mainline DHT rail (simulated)', network: true }),
  local: Object.freeze({ suffix: '.local', title: 'your own petname book', network: false }),
  key: Object.freeze({ suffix: '.key', title: 'self-certifying: the address is the key', network: false }),
});

export const NETWORK_RAILS = Object.freeze(Object.keys(RAILS).filter((rail) => RAILS[rail].network));

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export const isLabel = (text) => typeof text === 'string' && LABEL.test(text);

const keyAddress = (id) => ({ kind: 'key', rail: 'key', id, host: `${id}.key`, address: `key-web://${id}.key/` });

/** The self-certifying address of a key: always valid, needs no resolver, cannot be hijacked. */
export const addressOfKey = (id) => keyAddress(id).address;

/**
 * Reads an address the way a person types or pastes it: with or without
 * the scheme, any case, with or without a trailing path. Returns null for
 * anything that is not a key-web address, or one of:
 *
 *   {kind: 'key', rail: 'key', id, host, address}
 *   {kind: 'name', rail: 'at' | 'dht', app, publisher, host, address}
 *   {kind: 'petname', rail: 'local', label, host, address}
 */
export function parseAddress(text) {
  if (typeof text !== 'string') return null;
  let rest = text.trim().toLowerCase();
  const scheme = /^(key-web|isolated-app):\/\//.exec(rest);
  if (scheme) rest = rest.slice(scheme[0].length);
  else if (rest.includes(':')) return null;
  const host = rest.split(/[/?#]/)[0];
  if (isKeyId(host)) return keyAddress(host);
  // Chromium's scheme only ever names a key.
  if (scheme && scheme[1] === 'isolated-app') return null;
  const labels = host.split('.');
  const rail = labels[labels.length - 1];
  if (rail === 'key' && labels.length === 2 && isKeyId(labels[0])) return keyAddress(labels[0]);
  if (NETWORK_RAILS.includes(rail) && labels.length === 3 && isLabel(labels[0]) && isLabel(labels[1])) {
    return { kind: 'name', rail, app: labels[0], publisher: labels[1], host, address: `key-web://${host}/` };
  }
  if (rail === 'local' && labels.length === 2 && isLabel(labels[0])) {
    return { kind: 'petname', rail, label: labels[0], host, address: `key-web://${host}/` };
  }
  return null;
}

/** The bytes a publisher's signature on a name record covers. */
export const nameMessage = (payload) => utf8(`${NAME_FORMAT}\n${payload}`);

/**
 * What a rail would call the publisher, derived from the publisher's key
 * rather than taken from the rail: a did:plc-shaped identifier for the
 * ATProto rail, the key itself for the DHT rail. Both are simulated.
 */
export async function publisherAnchor(rail, publisherKey, subtle) {
  if (rail === 'at') return `did:plc:${base32(await sha256(publisherKey, subtle)).slice(0, 24)}`;
  return `pk:${idFromKey(publisherKey).slice(0, 52)}`;
}

/**
 * Checks a record a rail returned for one name. Never throws. A record
 * that passes proves only that some publisher key signed "this name is
 * this key": whether to believe it is the pin's decision, not this one's.
 *
 * Resolves with {ok, code, message, key, publisherKey, sequence, certificates}.
 */
export async function verifyNameRecord(record, { app, publisher, rail, subtle = globalThis.crypto.subtle } = {}) {
  const fail = (code, message) => ({ ok: false, code, message, key: null, publisherKey: null, sequence: null, certificates: [] });
  if (record === null || typeof record !== 'object' || Array.isArray(record) || record.format !== NAME_FORMAT) return fail('RECORD_MALFORMED', 'the answer is not a key-web name record');
  if (typeof record.payload !== 'string' || record.payload.length > 2048) return fail('RECORD_MALFORMED', 'the record has no payload');
  let publisherKey;
  let signature;
  try {
    publisherKey = base64Decode(record.publisher_key);
    signature = base64Decode(record.signature);
  } catch {
    return fail('RECORD_MALFORMED', 'the record is not signed');
  }
  if (publisherKey.length !== 32 || signature.length !== 64) return fail('RECORD_MALFORMED', 'the publisher key or the signature has the wrong length');
  let payload;
  try {
    payload = JSON.parse(record.payload);
  } catch {
    return fail('RECORD_MALFORMED', 'the payload is not JSON');
  }
  if (payload === null || typeof payload !== 'object') return fail('RECORD_MALFORMED', 'the payload is not an object');
  if (typeof payload.key !== 'string' || !ID_PATTERN.test(payload.key) || !isKeyId(payload.key)) return fail('RECORD_MALFORMED', 'the record does not name an Ed25519 key');
  if (!Number.isSafeInteger(payload.sequence) || payload.sequence < 1) return fail('RECORD_MALFORMED', 'the record has no sequence number');
  // A record for another name, or lifted from another rail, answers nothing.
  if (payload.app !== app || payload.publisher !== publisher || payload.rail !== rail) return fail('RECORD_WRONG_NAME', 'the record is for a different name than the one asked for');
  if (!(await verifyDetached(publisherKey, signature, nameMessage(record.payload), subtle))) {
    return fail('RECORD_SIGNATURE_INVALID', 'the record was changed after it was signed, or was not signed by the key it carries');
  }
  return {
    ok: true,
    code: 'RECORD_VERIFIED',
    message: 'signed by the publisher key it carries',
    key: payload.key,
    publisherKey,
    sequence: payload.sequence,
    certificates: Array.isArray(record.rotation) ? record.rotation.slice(0, 4) : [],
  };
}
