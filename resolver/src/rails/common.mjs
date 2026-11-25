// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Shared rail plumbing.
//
// A rail adapter answers one untrusted question:
//   resolve({ publisher, slug, store }) ->
//     { pdoc: Uint8Array, rec: Uint8Array, railId: string, via: string }
// `railId` is the rail-level identity that served the bytes (resolved DID,
// PKARR key, npub, or K_pub). The resolver checks it against the VERIFIED
// publisher document with railListed() (Spec §1.7.5 rail_handle_listed).

export class RailError extends Error {
  /**
   * @param {'RAIL_UNAVAILABLE'|'NOT_FOUND'|'UNKNOWN_ALIAS'|'TRANSPORT_INVALID'|'HANDLE_NOT_CLAIMED'|'BAD_INPUT'} code
   */
  constructor(code, message, { rail } = {}) {
    super(message);
    this.name = 'RailError';
    this.code = code;
    this.rail = rail;
  }
}

export const RAIL_BADGES = Object.freeze({ at: 'AT', dht: 'DHT', nostr: 'Nostr', local: 'Local', key: 'Key' });

/**
 * Does the verified publisher document list the rail identity that served it?
 * A handle, PKARR key or npub that the K_pub-signed rail map does not name is
 * never trusted to speak for K_pub.
 */
export function railListed(rail, doc, { publisher, railId }) {
  const rails = doc?.rails ?? {};
  switch (rail) {
    case 'at':
      return typeof rails.at?.handle === 'string' &&
        rails.at.handle.toLowerCase() === String(publisher).toLowerCase() &&
        rails.at.did === railId;
    case 'dht':
      return typeof rails.dht?.pkarr === 'string' && rails.dht.pkarr === railId;
    case 'nostr':
      return typeof rails.nostr?.npub === 'string' && rails.nostr.npub === railId;
    case 'local':
    case 'key':
      return doc.pub === railId;
    default:
      return false;
  }
}

/** Fetch with a timeout; returns the Response or throws RailError. */
export async function fetchWithTimeout(fetchImpl, url, { timeoutMs = 8000, rail, headers } = {}) {
  if (typeof fetchImpl !== 'function') throw new RailError('RAIL_UNAVAILABLE', 'no fetch implementation', { rail });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: controller.signal, redirect: 'error', headers });
    return res;
  } catch (e) {
    throw new RailError('RAIL_UNAVAILABLE', `${url}: ${e.message}`, { rail });
  } finally {
    clearTimeout(timer);
  }
}
