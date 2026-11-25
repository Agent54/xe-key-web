// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// An offline world for tests and `keyweb-resolve demo`: deterministic
// identities plus in-memory DNS, HTTPS, PKARR-relay and Nostr-relay
// transports, wired into the REAL rail adapters (AtRail, DhtRail,
// NostrRail). Nothing here touches the network.
//
// TEST VECTORS ONLY: every key below is derived from a public label with
// SHA-256 and is therefore known to everyone. Never use them for real data.
// Host names use the reserved `.example` / `.test` TLDs (RFC 2606).

import { utf8 } from './encoding.mjs';
import { ed25519, schnorr, sha256 } from './crypto.mjs';
import { kwIdForPubkey } from './ids.mjs';
import { incept, pubkeyOf, rotate, simpleTombstone, tombstone } from './kel.mjs';
import { signAppRecord, signPublisherDoc } from './records.mjs';
import { AtRail, DEFAULT_NSID, recordValue } from './rails/at.mjs';
import { DhtRail, buildKwPacket, pkarrKeyFor, signPkarrPacket } from './rails/dht.mjs';
import { NostrRail, D_PUBLISHER, dTagForApp, hexToNpub, kwEvent } from './rails/nostr.mjs';
import { hex } from './encoding.mjs';

export const testSeed = (label) => sha256(utf8.encode(`key-web public test vector: ${label}`));

/** A K-ED app identity (deterministic). */
export function makeApp(label) {
  const keyPair = ed25519.fromSeed(testSeed(`app/${label}`));
  return { keyPair, id: kwIdForPubkey(pubkeyOf(keyPair)) };
}

let didCounter = 0;
function plcDidFor(label) {
  // did:plc identifiers are 24 base32 chars; derive one from the label.
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  const h = sha256(utf8.encode(`did/${label}/${didCounter++}`));
  let s = '';
  for (let i = 0; i < 24; i++) s += alphabet[h[i] & 31];
  return `did:plc:${s}`;
}

/**
 * A publisher with rails on at / dht / nostr.
 * profile "K-ED": K_pub is an Ed25519 key (simple profile).
 * profile "K-SAID": K_pub is a KEL inception digest with a pre-committed
 * next key, so it can rotate without changing its kw-id.
 */
export function makePublisher(label, { profile = 'K-SAID', handle = `${label}.example`, rails = ['at', 'dht', 'nostr'] } = {}) {
  let generation = 0;
  const keyAt = (g) => ed25519.fromSeed(testSeed(`pub/${label}/key/${g}`));
  const pkarr = ed25519.fromSeed(testSeed(`pub/${label}/pkarr`));
  const nostrSecret = testSeed(`pub/${label}/nostr`);
  const did = plcDidFor(label);

  const p = {
    label,
    profile,
    handle,
    did,
    pkarr,
    pkarrKey: pkarrKeyFor(pkarr.publicKey),
    nostrSecret,
    npub: hexToNpub(hex.encode(schnorr.publicKey(nostrSecret))),
    signers: [keyAt(0)],
    kel: undefined,
    docSeq: 0,
  };
  if (profile === 'K-SAID') {
    const { kwId, event } = incept({ current: [keyAt(0)], next: [keyAt(1)] });
    p.id = kwId;
    p.kel = [event];
  } else {
    p.id = kwIdForPubkey(pubkeyOf(keyAt(0)));
  }

  p.railMap = () => ({
    ...(rails.includes('at') ? { at: { handle: p.handle, did: p.did } } : {}),
    ...(rails.includes('dht') ? { dht: { pkarr: p.pkarrKey } } : {}),
    ...(rails.includes('nostr') ? { nostr: { npub: p.npub } } : {}),
  });
  p.pdoc = ({ seq = ++p.docSeq, railMap = p.railMap(), kel = p.kel } = {}) =>
    signPublisherDoc({ pub: p.id, seq, rails: railMap, kel }, p.signers);
  p.app = (slug, appId, { seq = 1, succ } = {}) =>
    signAppRecord({ pub: p.id, slug, app: appId, seq, succ }, p.signers);

  /** KERI rotation: reveal the pre-committed next key, commit a new one. */
  p.rotate = () => {
    if (profile !== 'K-SAID') throw new Error('only K-SAID publishers rotate');
    generation += 1;
    const revealed = keyAt(generation);
    const next = keyAt(generation + 1);
    p.kel = [...p.kel, rotate(p.kel, { revealed: [revealed], next: [next] })];
    p.signers = [revealed];
    return p;
  };
  p.currentKey = () => p.signers[0];
  p.nextKey = () => keyAt(generation + 1);
  return p;
}

/** A K-SAID app identity with its own KEL (for succession proofs). */
export function makeSaidApp(label) {
  const k0 = ed25519.fromSeed(testSeed(`said-app/${label}/0`));
  const k1 = ed25519.fromSeed(testSeed(`said-app/${label}/1`));
  const { kwId, event } = incept({ current: [k0], next: [k1] });
  return {
    id: kwId,
    kel: [event],
    current: k0,
    next: k1,
    retireTo(successorId) {
      return [...this.kel, tombstone(this.kel, { revealed: [k1], successor: successorId })];
    },
  };
}

export { simpleTombstone };

/** In-memory internet: DNS TXT, HTTPS GET, PKARR relays, Nostr relays. */
export function createOfflineWorld({ nsid = DEFAULT_NSID, plcDirectory = 'https://plc.test', relay = 'https://pkarr-relay.test', nostrRelay = 'wss://nostr-relay.test' } = {}) {
  const txt = new Map();
  const http = new Map();
  const nostrEvents = [];
  const down = new Set();
  let clock = 1_700_000_000;

  const json = (body, status = 200) => ({ status, ok: status >= 200 && status < 300, json: async () => body, text: async () => JSON.stringify(body), arrayBuffer: async () => new ArrayBuffer(0) });
  const binary = (bytes) => ({ status: 200, ok: true, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), json: async () => { throw new Error('binary'); }, text: async () => '' });

  const world = {
    nsid,
    plcDirectory,
    relay,
    nostrRelay,
    down,

    async resolveTxt(name) {
      if (down.has('dns')) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
      const v = txt.get(name.toLowerCase());
      if (!v) throw Object.assign(new Error(`ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
      return v;
    },

    async fetch(url) {
      const host = new URL(url).host;
      if (down.has(host) || down.has('internet')) throw new TypeError('fetch failed');
      const handler = http.get(url);
      if (!handler) return json({ error: 'not found' }, 404);
      return handler();
    },

    async queryRelay(relayUrl, filter) {
      if (down.has(new URL(relayUrl).host) || down.has('internet')) throw new Error('connection failed');
      return nostrEvents.filter((ev) =>
        (!filter.kinds || filter.kinds.includes(ev.kind)) &&
        (!filter.authors || filter.authors.includes(ev.pubkey)) &&
        (!filter['#d'] || ev.tags.some((t) => t[0] === 'd' && filter['#d'].includes(t[1]))));
    },

    /** Publish a publisher + app records on the AT rail (handle -> DID -> PDS). */
    publishAt(pub, { pdoc, apps }, { pds = `https://pds-${pub.label}.test`, claimHandle = true, handle = pub.handle, did = pub.did } = {}) {
      txt.set(`_atproto.${handle}`.toLowerCase(), [[`did=${did}`]]);
      http.set(`${plcDirectory}/${did}`, () => json({
        id: did,
        alsoKnownAs: claimHandle ? [`at://${handle}`] : [],
        service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds }],
      }));
      const rec = (collection, rkey, bytes) => {
        const u = new URL('/xrpc/com.atproto.repo.getRecord', pds);
        u.searchParams.set('repo', did);
        u.searchParams.set('collection', collection);
        u.searchParams.set('rkey', rkey);
        http.set(u.toString(), () => json({ uri: `at://${did}/${collection}/${rkey}`, cid: 'bafytest', value: recordValue(collection, bytes) }));
      };
      rec(`${nsid}.publisher`, 'self', pdoc);
      for (const [slug, bytes] of Object.entries(apps)) rec(`${nsid}.app`, slug, bytes);
    },

    /** Publish a signed PKARR packet for the publisher's PKARR key. */
    publishDht(pub, { pdoc, apps }, { includePublisher = true, signer = pub.pkarr, seq } = {}) {
      const packet = buildKwPacket(pub.pkarrKey, { pdoc: includePublisher ? pdoc : undefined, apps });
      const body = signPkarrPacket(signer, packet, seq ?? BigInt(++clock) * 1_000_000n);
      http.set(`${relay}/${pub.pkarrKey}`, () => binary(body));
      return body;
    },

    /** Publish Nostr kind-30078 events signed by the publisher's npub key. */
    publishNostr(pub, { pdoc, apps }, { secret = pub.nostrSecret } = {}) {
      const created_at = ++clock;
      nostrEvents.push(kwEvent(secret, { dTag: D_PUBLISHER, bytes: pdoc, created_at }));
      for (const [slug, bytes] of Object.entries(apps)) {
        nostrEvents.push(kwEvent(secret, { dTag: dTagForApp(slug), bytes, created_at }));
      }
    },

    /** Publish the same signed bytes on every rail the publisher uses. */
    publishEverywhere(pub, records) {
      world.publishAt(pub, records);
      // K-SAID publisher documents carry a KEL and exceed PKARR's 1000 bytes.
      // Records that still do not fit (e.g. an app record carrying a full
      // succession KEL) are simply not published on the dht rail; the
      // previous packet stays there, exactly as with a real publisher.
      try {
        world.publishDht(pub, records, { includePublisher: pub.profile !== 'K-SAID' });
        world.dhtSkipped = null;
      } catch (e) {
        if (e.code !== 'BAD_INPUT') throw e;
        world.dhtSkipped = e.message;
      }
      world.publishNostr(pub, records);
    },

    /** Real adapters over the in-memory transports. */
    rails() {
      return {
        at: new AtRail({ fetch: world.fetch, resolveTxt: world.resolveTxt, plcDirectory, nsid }),
        dht: new DhtRail({ fetch: world.fetch, relays: [relay] }),
        nostr: new NostrRail({ queryRelay: world.queryRelay, relays: [nostrRelay] }),
      };
    },

    rawHttp: http,
    rawTxt: txt,
    rawNostr: nostrEvents,
  };
  return world;
}
