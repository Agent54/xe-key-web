// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// The resolver's local trust state (Spec §1.7.7): the publisher book and the
// TOFU binding store. It is the reason a hijacked handle fails closed and the
// reason `.dht` keeps working when every `.at` dependency is down.
//
//   petnames    user-assigned label -> K_pub            (the `.local` rail)
//   aliases     "<rail>:<label>" -> K_pub               learned ONLY from
//               verified publisher documents (rail maps)
//   publishers  K_pub -> { kel, seq, rails, doc }       last verified state
//   bindings    "<K_pub>/<slug>" -> { app, seq, evidence, pinned, ... }
//   names       "<name host>" -> "<K_pub>/<slug>"
//
// Everything derives from the KEY: names only point at bindings.
// JSON-persistable; bytes are stored as base64url dCBOR.

import fs from 'node:fs';
import path from 'node:path';
import { decode, encode } from './cbor.mjs';
import { base64url } from './encoding.mjs';

const VERSION = 1;

const empty = () => ({ version: VERSION, petnames: {}, aliases: {}, publishers: {}, bindings: {}, names: {} });

export const bindingKey = (pub, slug) => `${pub}/${slug}`;

export class TrustStore {
  /** @param {{ file?: string, now?: () => number }} [options] */
  constructor({ file, now = () => Math.floor(Date.now() / 1000) } = {}) {
    this.file = file ?? null;
    this.now = now;
    this.data = empty();
    if (this.file && fs.existsSync(this.file)) this.data = TrustStore.validate(JSON.parse(fs.readFileSync(this.file, 'utf8')));
  }

  static validate(json) {
    if (!json || json.version !== VERSION) throw new Error('trust store: unsupported version');
    for (const k of ['petnames', 'aliases', 'publishers', 'bindings', 'names']) {
      if (!json[k] || typeof json[k] !== 'object' || Array.isArray(json[k])) throw new Error(`trust store: bad ${k}`);
    }
    return json;
  }

  save() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(this.data, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  // --- petnames (.local) ---------------------------------------------------

  setPetname(label, pub) {
    this.data.petnames[label.toLowerCase()] = pub;
  }

  petname(label) {
    return this.data.petnames[label.toLowerCase()] ?? null;
  }

  // --- aliases learned from verified rail maps ------------------------------

  publisherForAlias(rail, label) {
    return this.data.aliases[`${rail}:${label.toLowerCase()}`] ?? null;
  }

  /**
   * Learn every name a VERIFIED publisher document vouches for. Besides each
   * rail's own identity (handle, PKARR key, npub, NIP-05), the ATProto handle
   * and its first label become short aliases on the other rails, which is
   * what makes `cool-site.alice.dht` equivalent to `cool-site.alice.example`.
   */
  learnRails(doc) {
    const pub = doc.pub;
    const set = (rail, label) => {
      if (!label) return;
      const key = `${rail}:${String(label).toLowerCase()}`;
      // Never silently re-point an alias to a different key.
      if (!this.data.aliases[key]) this.data.aliases[key] = pub;
    };
    const rails = doc.rails ?? {};
    const shortNames = [];
    if (rails.at?.handle) {
      const handle = rails.at.handle.toLowerCase();
      set('at', handle);
      shortNames.push(handle, handle.split('.')[0]);
    }
    if (rails.nostr?.nip05) {
      const [name, domain] = String(rails.nostr.nip05).toLowerCase().split('@');
      if (name && domain) shortNames.push(`${name}.${domain}`);
    }
    if (rails.dht?.pkarr) set('dht', rails.dht.pkarr);
    if (rails.nostr?.npub) set('nostr', rails.nostr.npub);
    for (const name of shortNames) {
      if (rails.dht?.pkarr) set('dht', name);
      if (rails.nostr?.npub) set('nostr', name);
    }
    set('key', pub);
  }

  // --- publishers ---------------------------------------------------------------

  publisher(pub) {
    const p = this.data.publishers[pub];
    if (!p) return null;
    return {
      ...p,
      kel: p.kel ? decode(base64url.decode(p.kel)) : undefined,
      doc: p.doc ? base64url.decode(p.doc) : undefined,
    };
  }

  knownKel(pub) {
    return this.publisher(pub)?.kel;
  }

  putPublisher(doc, docBytes, kel) {
    const prev = this.data.publishers[doc.pub];
    if (prev && prev.seq > doc.seq) return; // never roll the rail map back
    this.data.publishers[doc.pub] = {
      seq: doc.seq,
      rails: JSON.parse(JSON.stringify(doc.rails)),
      kel: kel ? base64url.encode(encode(kel)) : null,
      doc: base64url.encode(docBytes),
      firstSeen: prev?.firstSeen ?? this.now(),
      lastSeen: this.now(),
    };
    this.learnRails(doc);
  }

  // --- bindings (TOFU / pinned) -----------------------------------------------

  binding(pub, slug) {
    return this.data.bindings[bindingKey(pub, slug)] ?? null;
  }

  bindingForName(name) {
    const key = this.data.names[name];
    return key ? { key, ...this.data.bindings[key] } : null;
  }

  cachedRecords(pub, slug) {
    const p = this.data.publishers[pub];
    const b = this.binding(pub, slug);
    if (!p?.doc || !b?.record) return null;
    return { pdoc: base64url.decode(p.doc), rec: base64url.decode(b.record) };
  }

  bind({ name, pub, slug, app, seq, recordBytes, rail, evidence, pinned }) {
    const key = bindingKey(pub, slug);
    const prev = this.data.bindings[key];
    const now = this.now();
    const rails = new Set(prev?.rails ?? []);
    rails.add(rail);
    this.data.bindings[key] = {
      pub,
      slug,
      app,
      seq: Math.max(seq, prev?.app === app ? prev.seq : 0),
      record: recordBytes ? base64url.encode(recordBytes) : prev?.record,
      rails: [...rails].sort(),
      evidence: prev?.evidence === 'pin' ? 'pin' : evidence,
      pinned: Boolean(prev?.pinned || pinned),
      contested: false,
      firstSeen: prev?.app === app ? prev.firstSeen : now,
      lastSeen: now,
    };
    if (name) this.data.names[name] = key;
  }

  markContested(pub, slug, answers) {
    const b = this.binding(pub, slug);
    if (b) {
      b.contested = true;
      b.disagreements = answers;
    }
  }

  /** "Forget this app": removes every binding and name that points at `app`. */
  forgetApp(app) {
    for (const [key, b] of Object.entries(this.data.bindings)) {
      if (b.app !== app) continue;
      delete this.data.bindings[key];
      for (const [name, target] of Object.entries(this.data.names)) {
        if (target === key) delete this.data.names[name];
      }
    }
  }
}
