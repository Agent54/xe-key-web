// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `nostr` rail: addressable events signed by the publisher's npub.
//
//   publisher label  npub1... (63 chars, fits one DNS label; self-certifying),
//                    a NIP-05 name written as labels (`alice.example.com`
//                    -> alice@example.com, DNS-anchored), or a short alias
//                    learned from a verified rail map
//   events           kind 30078 (NIP-78 addressable app data; the final kind
//                    number is TBD, Spec App. B #6) with tags
//                      ["d","key-web/publisher"]   -> publisher document
//                      ["d","key-web/app/<slug>"]  -> app record
//                    content = base64url(signed dCBOR)
//   transport check  NIP-01 event id + BIP-340 Schnorr signature by the npub
//
// Authenticity still comes from the K_pub signature inside the content.

import { base64url, bech32, hex, utf8 } from '../encoding.mjs';
import { schnorr, sha256 } from '../crypto.mjs';
import { RailError, fetchWithTimeout } from './common.mjs';

export const KW_EVENT_KIND = 30078;
export const D_PUBLISHER = 'key-web/publisher';
export const dTagForApp = (slug) => `key-web/app/${slug}`;

export function npubToHex(npub) {
  let decoded;
  try {
    decoded = bech32.decode(npub);
  } catch (e) {
    throw new RailError('BAD_INPUT', `invalid npub: ${e.message}`, { rail: 'nostr' });
  }
  if (decoded.hrp !== 'npub' || decoded.data.length !== 32) {
    throw new RailError('BAD_INPUT', 'npub must encode a 32-byte key', { rail: 'nostr' });
  }
  return hex.encode(decoded.data);
}

export const hexToNpub = (pubkeyHex) => bech32.encode('npub', hex.decode(pubkeyHex));

/** NIP-01: sha256 of the canonical JSON array. */
export function eventId(ev) {
  return hex.encode(sha256(utf8.encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
}

export function verifyEvent(ev) {
  if (!ev || typeof ev !== 'object') return false;
  if (!/^[0-9a-f]{64}$/.test(ev.pubkey ?? '') || !/^[0-9a-f]{64}$/.test(ev.id ?? '') || !/^[0-9a-f]{128}$/.test(ev.sig ?? '')) return false;
  if (!Number.isSafeInteger(ev.created_at) || !Number.isSafeInteger(ev.kind) || !Array.isArray(ev.tags) || typeof ev.content !== 'string') return false;
  if (eventId(ev) !== ev.id) return false;
  return schnorr.verify(hex.decode(ev.sig), hex.decode(ev.id), hex.decode(ev.pubkey));
}

/** Sign an event (publisher tooling and tests). */
export function signEvent(secretKey, { created_at, kind = KW_EVENT_KIND, tags, content }) {
  const pubkey = hex.encode(schnorr.publicKey(secretKey));
  const ev = { pubkey, created_at, kind, tags, content };
  ev.id = eventId(ev);
  ev.sig = hex.encode(schnorr.sign(hex.decode(ev.id), secretKey));
  return ev;
}

export function kwEvent(secretKey, { dTag, bytes, created_at }) {
  return signEvent(secretKey, { created_at, tags: [['d', dTag]], content: base64url.encode(bytes) });
}

/** NIP-05 `/.well-known/nostr.json` response -> hex pubkey for `name`. */
export function parseNip05(json, name) {
  const key = json?.names?.[name];
  if (typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key)) {
    throw new RailError('NOT_FOUND', `NIP-05 has no key for ${name}`, { rail: 'nostr' });
  }
  return key;
}

/** Newest valid event from `pubkey` with the given `d` tag. */
export function pickEvent(events, { pubkey, dTag, kind = KW_EVENT_KIND }) {
  const candidates = (events ?? []).filter((ev) =>
    ev?.pubkey === pubkey && ev.kind === kind &&
    Array.isArray(ev.tags) && ev.tags.some((t) => Array.isArray(t) && t[0] === 'd' && t[1] === dTag) &&
    verifyEvent(ev));
  candidates.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1));
  return candidates[0] ?? null;
}

/** Default relay transport: one REQ over a WebSocket, collected until EOSE. */
export function webSocketQuery(relayUrl, filter, { timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    if (typeof WebSocket !== 'function') {
      reject(new RailError('RAIL_UNAVAILABLE', 'no WebSocket implementation', { rail: 'nostr' }));
      return;
    }
    const sub = `kw${Math.random().toString(36).slice(2, 10)}`;
    const events = [];
    const ws = new WebSocket(relayUrl);
    const done = (err) => {
      clearTimeout(timer);
      try { ws.close(); } catch { /* ignore */ }
      if (err) reject(err); else resolve(events);
    };
    const timer = setTimeout(() => done(new RailError('RAIL_UNAVAILABLE', `${relayUrl}: timeout`, { rail: 'nostr' })), timeoutMs);
    ws.addEventListener('open', () => ws.send(JSON.stringify(['REQ', sub, filter])));
    ws.addEventListener('error', () => done(new RailError('RAIL_UNAVAILABLE', `${relayUrl}: connection failed`, { rail: 'nostr' })));
    ws.addEventListener('message', (msg) => {
      let data;
      try { data = JSON.parse(String(msg.data)); } catch { return; }
      if (data[0] === 'EVENT' && data[1] === sub) events.push(data[2]);
      if (data[0] === 'EOSE' && data[1] === sub) {
        try { ws.send(JSON.stringify(['CLOSE', sub])); } catch { /* ignore */ }
        done();
      }
    });
  });
}

export class NostrRail {
  /**
   * @param {{ relays?: string[], queryRelay?: (relay: string, filter: object) => Promise<object[]>,
   *           fetch?: typeof fetch, kind?: number, timeoutMs?: number }} [options]
   */
  constructor({ relays = [], queryRelay = webSocketQuery, fetch: fetchImpl = globalThis.fetch, kind = KW_EVENT_KIND, timeoutMs = 8000 } = {}) {
    this.name = 'nostr';
    this.relays = relays;
    this.queryRelay = queryRelay;
    this.fetch = fetchImpl;
    this.kind = kind;
    this.timeoutMs = timeoutMs;
  }

  async pubkeyForLabel(publisher, store) {
    if (publisher.startsWith('npub1')) return { pubkey: npubToHex(publisher), npub: publisher };
    const pub = store?.publisherForAlias('nostr', publisher);
    const npub = pub ? store.publisher(pub)?.rails?.nostr?.npub : null;
    if (npub) return { pubkey: npubToHex(npub), npub };
    const labels = publisher.split('.');
    if (labels.length >= 3) {
      // NIP-05 written as labels: name.domain.tld -> name@domain.tld
      const [name, ...domain] = labels;
      const url = `https://${domain.join('.')}/.well-known/nostr.json?name=${encodeURIComponent(name)}`;
      const res = await fetchWithTimeout(this.fetch, url, { rail: 'nostr', timeoutMs: this.timeoutMs });
      if (!res.ok) throw new RailError('NOT_FOUND', `${url}: HTTP ${res.status}`, { rail: 'nostr' });
      const pubkey = parseNip05(await res.json(), name);
      return { pubkey, npub: hexToNpub(pubkey) };
    }
    throw new RailError('UNKNOWN_ALIAS', `"${publisher}" is not an npub, a NIP-05 name, or a learned alias`, { rail: 'nostr' });
  }

  async resolve({ publisher, slug, store }) {
    if (this.relays.length === 0) {
      throw new RailError('RAIL_UNAVAILABLE', 'no Nostr relays configured (set KEYWEB_NOSTR_RELAYS)', { rail: 'nostr' });
    }
    const { pubkey, npub } = await this.pubkeyForLabel(publisher, store);
    const filter = { kinds: [this.kind], authors: [pubkey], '#d': [D_PUBLISHER, dTagForApp(slug)] };
    const results = await Promise.allSettled(this.relays.map((r) => this.queryRelay(r, filter)));
    const events = results.flatMap((r) => (r.status === 'fulfilled' && Array.isArray(r.value) ? r.value : []));
    if (events.length === 0 && results.every((r) => r.status === 'rejected')) {
      throw new RailError('RAIL_UNAVAILABLE', 'no Nostr relay answered', { rail: 'nostr' });
    }
    const pEv = pickEvent(events, { pubkey, dTag: D_PUBLISHER, kind: this.kind });
    const aEv = pickEvent(events, { pubkey, dTag: dTagForApp(slug), kind: this.kind });
    if (!pEv || !aEv) throw new RailError('NOT_FOUND', `no valid key-web events for ${slug}`, { rail: 'nostr' });
    try {
      return { pdoc: base64url.decode(pEv.content), rec: base64url.decode(aEv.content), railId: npub, via: 'nostr-relays' };
    } catch {
      throw new RailError('TRANSPORT_INVALID', 'event content is not base64url', { rail: 'nostr' });
    }
  }

  labelFromRails(rails) {
    return rails?.nostr?.npub ?? null;
  }
}
