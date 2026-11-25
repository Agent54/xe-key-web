// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `key` rail: self-certifying base32 identities.
//
//   key-web://<kw-id>.key/            the key URL itself: no lookup at all
//   key-web://<slug>.<K_pub>.key/     an app under a self-certifying
//                                     publisher key; records come from the
//                                     trust store or from any rail that the
//                                     publisher's verified rail map lists
//
// The publisher label IS K_pub, so railListed() only accepts a publisher
// document whose `pub` equals the label.

import { RailError } from './common.mjs';
import { isKwId } from '../ids.mjs';

export class KeyRail {
  /**
   * @param {{ fallback?: (rail: string, label: string, slug: string) => Promise<object> }} [options]
   *   `fallback` lets the resolver fetch through other rails named by the
   *   publisher's last verified rail map.
   */
  constructor({ fallback } = {}) {
    this.name = 'key';
    this.fallback = fallback ?? null;
  }

  async resolve({ publisher, slug, store }) {
    if (!isKwId(publisher)) throw new RailError('BAD_INPUT', 'the .key rail needs a kw-id publisher label', { rail: 'key' });
    const cached = store?.cachedRecords(publisher, slug);
    if (cached) return { ...cached, railId: publisher, via: 'trust-store' };
    const known = store?.publisher(publisher);
    if (known && this.fallback) {
      let lastError = null;
      for (const rail of ['dht', 'nostr', 'at']) {
        const label = rail === 'at' ? known.rails?.at?.handle : rail === 'dht' ? known.rails?.dht?.pkarr : known.rails?.nostr?.npub;
        if (!label) continue;
        try {
          const got = await this.fallback(rail, label, slug);
          return { pdoc: got.pdoc, rec: got.rec, railId: publisher, via: `${rail}:${got.via ?? label}` };
        } catch (e) {
          lastError = e;
        }
      }
      if (lastError) throw lastError;
    }
    throw new RailError('NOT_FOUND', `no records known for ${slug} under ${publisher}`, { rail: 'key' });
  }

  labelFromRails() {
    return null;
  }
}
