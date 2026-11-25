// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `dht` rail: PKARR signed DNS packets, stored as BEP-44 mutable items on
// Mainline DHT and served by PKARR relays.
//
//   publisher label   the PKARR key itself (52 chars of z-base32), or a short
//                     alias learned earlier from a verified rail map
//   relay wire format sig(64) || seq(8, big-endian, microseconds) || packet
//   BEP-44 signature  Ed25519 over bencode "3:seqi<seq>e1:v<len>:" || packet
//   records           TXT _kwpub.<key>        -> "kw1=" base64url(publisher doc)
//                     TXT _kwapp.<slug>.<key> -> "kw1=" base64url(app record)
//                     (split into <=255-byte strings, concatenated on read)
//
// The PKARR signature is a transport check: a relay cannot forge or alter a
// packet, but authenticity still comes from the K_pub signature inside.
// This adapter talks to relays over HTTPS. Native BEP-44 `get` over UDP uses
// the same packet format and is left to a host that can open UDP sockets.

import { base64url, concat, utf8, zbase32 } from '../encoding.mjs';
import { ed25519 } from '../crypto.mjs';
import { decodePacket, encodePacket } from './dns.mjs';
import { RailError, fetchWithTimeout } from './common.mjs';

export const PKARR_MAX_PACKET = 1000;
const TXT_PREFIX = 'kw1=';

export function parsePkarrKey(label) {
  if (typeof label !== 'string' || label.length !== 52) return null;
  try {
    const key = zbase32.decode(label);
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

export const pkarrKeyFor = (publicKey) => zbase32.encode(publicKey);

export function bep44Signable(seq, packet) {
  return concat(utf8.encode(`3:seqi${BigInt(seq)}e1:v${packet.length}:`), packet);
}

function splitTxt(text) {
  const out = [];
  for (let i = 0; i < text.length; i += 255) out.push(text.slice(i, i + 255));
  return out;
}

/** Build the DNS packet a publisher would sign (for tooling and tests). */
export function buildKwPacket(z32Key, { pdoc, apps = {} }) {
  const answers = [];
  if (pdoc) answers.push({ name: `_kwpub.${z32Key}`, txt: splitTxt(TXT_PREFIX + base64url.encode(pdoc)) });
  for (const [slug, rec] of Object.entries(apps)) {
    answers.push({ name: `_kwapp.${slug}.${z32Key}`, txt: splitTxt(TXT_PREFIX + base64url.encode(rec)) });
  }
  const packet = encodePacket({ answers });
  if (packet.length > PKARR_MAX_PACKET) {
    throw new RailError('BAD_INPUT', `PKARR packets are limited to ${PKARR_MAX_PACKET} bytes (got ${packet.length})`, { rail: 'dht' });
  }
  return packet;
}

/** Sign a packet into the relay wire format. `seq` is in microseconds. */
export function signPkarrPacket(keyPair, packet, seq = BigInt(Date.now()) * 1000n) {
  const seqBytes = new Uint8Array(8);
  new DataView(seqBytes.buffer).setBigUint64(0, BigInt(seq));
  return concat(ed25519.sign(keyPair, bep44Signable(seq, packet)), seqBytes, packet);
}

/** Verify a relay response for `z32Key`. Returns { seq, packet }. */
export function parseSignedPacket(z32Key, body) {
  const key = parsePkarrKey(z32Key);
  if (!key) throw new RailError('BAD_INPUT', 'not a PKARR key', { rail: 'dht' });
  if (!(body instanceof Uint8Array) || body.length < 72 || body.length > 72 + PKARR_MAX_PACKET) {
    throw new RailError('TRANSPORT_INVALID', 'PKARR packet has an invalid size', { rail: 'dht' });
  }
  const sig = body.subarray(0, 64);
  const seq = new DataView(body.buffer, body.byteOffset + 64, 8).getBigUint64(0);
  const packet = body.slice(72);
  if (!ed25519.verify(key, bep44Signable(seq, packet), sig)) {
    throw new RailError('TRANSPORT_INVALID', 'PKARR packet signature is invalid', { rail: 'dht' });
  }
  return { seq, packet };
}

/** Pull the publisher document and the app record for `slug` out of a packet. */
export function extractKwRecords(z32Key, packet, slug) {
  let answers;
  try {
    ({ answers } = decodePacket(packet));
  } catch (e) {
    throw new RailError('TRANSPORT_INVALID', `PKARR packet: ${e.message}`, { rail: 'dht' });
  }
  const suffix = `.${z32Key.toLowerCase()}`;
  const find = (name) => {
    const hits = answers.filter((a) => a.txt && (a.name === name || a.name === name + suffix));
    if (hits.length === 0) return null;
    if (hits.length > 1) throw new RailError('TRANSPORT_INVALID', `duplicate ${name} records`, { rail: 'dht' });
    const text = hits[0].txt.join('');
    if (!text.startsWith(TXT_PREFIX)) throw new RailError('TRANSPORT_INVALID', `${name} is not a kw1 record`, { rail: 'dht' });
    try {
      return base64url.decode(text.slice(TXT_PREFIX.length));
    } catch {
      throw new RailError('TRANSPORT_INVALID', `${name} is not base64url`, { rail: 'dht' });
    }
  };
  const pdoc = find('_kwpub');
  const rec = find(`_kwapp.${slug}`);
  if (!rec) throw new RailError('NOT_FOUND', `no key-web app record for ${slug} under ${z32Key}`, { rail: 'dht' });
  return { pdoc, rec };
}

export class DhtRail {
  /** @param {{ relays?: string[], fetch?: typeof fetch, timeoutMs?: number }} [options] */
  constructor({ relays = [], fetch: fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {}) {
    this.name = 'dht';
    this.relays = relays;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  keyForLabel(publisher, store) {
    if (parsePkarrKey(publisher)) return publisher;
    const pub = store?.publisherForAlias('dht', publisher);
    const pkarr = pub ? store.publisher(pub)?.rails?.dht?.pkarr : null;
    if (!pkarr) {
      throw new RailError('UNKNOWN_ALIAS',
        `"${publisher}" is not a PKARR key and no verified rail map has introduced it; use the 52-char key, a pin, or resolve another rail first`,
        { rail: 'dht' });
    }
    return pkarr;
  }

  async fetchPacket(z32Key) {
    if (this.relays.length === 0) {
      throw new RailError('RAIL_UNAVAILABLE', 'no PKARR relays configured (set KEYWEB_PKARR_RELAYS)', { rail: 'dht' });
    }
    let best = null;
    let lastError = null;
    for (const relay of this.relays) {
      try {
        const res = await fetchWithTimeout(this.fetch, `${relay.replace(/\/$/, '')}/${z32Key}`, { rail: 'dht', timeoutMs: this.timeoutMs });
        if (!res.ok) throw new RailError(res.status === 404 ? 'NOT_FOUND' : 'RAIL_UNAVAILABLE', `${relay}: HTTP ${res.status}`, { rail: 'dht' });
        const signed = parseSignedPacket(z32Key, new Uint8Array(await res.arrayBuffer()));
        if (!best || signed.seq > best.seq) best = { ...signed, relay };
      } catch (e) {
        lastError = e;
      }
    }
    if (!best) throw lastError ?? new RailError('NOT_FOUND', 'no relay had the packet', { rail: 'dht' });
    return best;
  }

  /**
   * `pdocHint`: a publisher document obtained from another rail in the same
   * resolution. It is only bytes; the resolver re-verifies it and requires
   * its signed rail map to name exactly this PKARR key.
   */
  async resolve({ publisher, slug, store, pdocHint }) {
    const z32Key = this.keyForLabel(publisher, store);
    const { packet, relay } = await this.fetchPacket(z32Key);
    let { pdoc, rec } = extractKwRecords(z32Key, packet, slug);
    if (!pdoc) {
      // A K-SAID publisher document (with its KEL) rarely fits in 1000 bytes.
      // Fall back to a publisher document from elsewhere; it must still verify
      // and list this PKARR key in its rail map.
      // Prefer the document from the current resolution (it may carry a newer
      // KEL, e.g. after a rotation) over the cached one.
      const pub = store?.publisherForAlias('dht', z32Key);
      const known = pub ? store.publisher(pub) : null;
      if (pdocHint) pdoc = pdocHint;
      else if (known?.doc && known.rails?.dht?.pkarr === z32Key) pdoc = known.doc;
      else throw new RailError('NOT_FOUND', `no publisher document under ${z32Key}`, { rail: 'dht' });
    }
    return { pdoc, rec, railId: z32Key, via: relay };
  }

  labelFromRails(rails) {
    return rails?.dht?.pkarr ?? null;
  }
}
