// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Offline, deterministic rail for tests, demos and air-gapped use. It speaks
// the same adapter contract as the real rails and is checked by the resolver
// with the same railListed() rules, so a mock named "at" must return a DID as
// its railId, a mock "dht" a PKARR key, and so on.
//
// Fixture JSON (CLI --fixtures):
//   { "rails": { "at": { "<publisher>|<slug>": { "pdoc": "<b64url>", "rec": "<b64url>", "railId": "did:plc:..." } } },
//     "down": ["nostr"] }

import { base64url } from '../encoding.mjs';
import { RailError } from './common.mjs';

export class MockRail {
  constructor(name, { entries = {}, down = false, labelFromRails } = {}) {
    this.name = name;
    this.entries = new Map(Object.entries(entries));
    this.down = down;
    this.calls = [];
    this._labelFromRails = labelFromRails ?? null;
  }

  set(publisher, slug, entry) {
    this.entries.set(`${publisher.toLowerCase()}|${slug}`, entry);
    return this;
  }

  delete(publisher, slug) {
    this.entries.delete(`${publisher.toLowerCase()}|${slug}`);
    return this;
  }

  setDown(down) {
    this.down = down;
    return this;
  }

  async resolve({ publisher, slug, store }) {
    this.calls.push({ publisher, slug });
    if (this.down) throw new RailError('RAIL_UNAVAILABLE', `${this.name} rail is down`, { rail: this.name });
    let entry = this.entries.get(`${publisher.toLowerCase()}|${slug}`);
    if (!entry && store) {
      // Mirror the real adapters: short labels resolve through aliases learned
      // from verified rail maps.
      const pub = store.publisherForAlias(this.name, publisher);
      const label = pub ? this.labelFromRails(store.publisher(pub)?.rails) : null;
      if (label) entry = this.entries.get(`${label.toLowerCase()}|${slug}`);
    }
    if (!entry) throw new RailError('NOT_FOUND', `${this.name}: nothing for ${publisher}/${slug}`, { rail: this.name });
    return { pdoc: entry.pdoc, rec: entry.rec, railId: entry.railId, via: `mock:${this.name}` };
  }

  labelFromRails(rails) {
    if (this._labelFromRails) return this._labelFromRails(rails);
    if (this.name === 'at') return rails?.at?.handle ?? null;
    if (this.name === 'dht') return rails?.dht?.pkarr ?? null;
    if (this.name === 'nostr') return rails?.nostr?.npub ?? null;
    return null;
  }

  static fromFixtures(json) {
    const rails = {};
    const down = new Set(json?.down ?? []);
    for (const [name, entries] of Object.entries(json?.rails ?? {})) {
      const decoded = {};
      for (const [key, e] of Object.entries(entries)) {
        decoded[key.toLowerCase()] = { pdoc: base64url.decode(e.pdoc), rec: base64url.decode(e.rec), railId: e.railId };
      }
      rails[name] = new MockRail(name, { entries: decoded, down: down.has(name) });
    }
    return rails;
  }
}
