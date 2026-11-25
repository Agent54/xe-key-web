// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// @key-web/resolver: zero-dependency multi-rail resolver for
//   key-web://<app-slug>.<publisher>[.<rail>]/   ->   key-web://<K_app>.key/

export { KeyWebResolver, FAIL_CLOSED_CODES } from './resolver.mjs';
export { TrustStore } from './store.mjs';
export { parseKeyWebUrl, canonicalKeyUrl, shareLink, KeyWebUrlError, RESERVED_RAILS, ALL_RAILS } from './url.mjs';
export { parseKwId, isKwId, kwIdFor, kwIdForPubkey, pinFor, pinMatches, fingerprint, MIN_PIN_LENGTH, SHARE_PIN_LENGTH } from './ids.mjs';
export { signPublisherDoc, signAppRecord, verifyPublisherDoc, verifyAppRecord, inspectRecord, RecordError } from './records.mjs';
export { incept, rotate, tombstone, simpleTombstone, evaluateKel, mergeKel, keyStateFor, successionProven, pubkeyOf, KelError } from './kel.mjs';
export { ed25519, p256, schnorr, sha256, sha512 } from './crypto.mjs';
export { encode as cborEncode, decode as cborDecode, CborError } from './cbor.mjs';
export { base32, zbase32, base64url, base64, hex, bech32 } from './encoding.mjs';
export { RailError, railListed, RAIL_BADGES } from './rails/common.mjs';
export { AtRail } from './rails/at.mjs';
export { DhtRail, pkarrKeyFor, buildKwPacket, signPkarrPacket, parseSignedPacket } from './rails/dht.mjs';
export { NostrRail, npubToHex, hexToNpub, kwEvent, verifyEvent } from './rails/nostr.mjs';
export { LocalRail, parsePublisherBook, bookEntry } from './rails/local.mjs';
export { KeyRail } from './rails/key.mjs';
export { MockRail } from './rails/mock.mjs';

import { AtRail } from './rails/at.mjs';
import { DhtRail } from './rails/dht.mjs';
import { NostrRail } from './rails/nostr.mjs';
import { LocalRail } from './rails/local.mjs';

const list = (value) => String(value ?? '').split(',').map((s) => s.trim()).filter(Boolean);

/**
 * Real network adapters. Nothing is hard-coded except the public PLC
 * directory default; PKARR and Nostr relays must be supplied explicitly
 * (options or KEYWEB_PKARR_RELAYS / KEYWEB_NOSTR_RELAYS, comma-separated).
 */
export function createLiveRails({ env = process.env, book, fetch: fetchImpl = globalThis.fetch, resolveTxt } = {}) {
  return {
    at: new AtRail({ fetch: fetchImpl, resolveTxt, plcDirectory: env.KEYWEB_PLC_DIRECTORY || undefined, nsid: env.KEYWEB_AT_NSID || undefined }),
    dht: new DhtRail({ fetch: fetchImpl, relays: list(env.KEYWEB_PKARR_RELAYS) }),
    nostr: new NostrRail({ fetch: fetchImpl, relays: list(env.KEYWEB_NOSTR_RELAYS) }),
    local: new LocalRail({ book }),
  };
}
