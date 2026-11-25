// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `local` rail: the user's own publisher book. Nothing remote.
//
// Publisher book JSON (also accepted as a `.kwname` import file):
//   {
//     "t": "kw-publisher-book/1",
//     "petnames": { "mom": "<K_pub kw-id>" },
//     "records": {
//       "<K_pub kw-id>": {
//         "publisher": "<base64url signed publisher document>",
//         "apps": { "<slug>": "<base64url signed app record>" }
//       }
//     }
//   }
// A petname is user-assigned, so `cool-site.mom.local` is self-certifying for
// THIS user; `.local` names mean different things on different devices and
// are never offered for sharing (the share link becomes a pinned key URL).

import { base64url } from '../encoding.mjs';
import { isKwId } from '../ids.mjs';
import { RailError } from './common.mjs';

export const BOOK_TYPE = 'kw-publisher-book/1';
const PETNAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

/** Strictly validate a publisher book; returns a normalized copy. */
export function parsePublisherBook(json) {
  const fail = (msg) => { throw new RailError('BAD_INPUT', `publisher book: ${msg}`, { rail: 'local' }); };
  if (!json || typeof json !== 'object' || json.t !== BOOK_TYPE) fail(`expected "t": "${BOOK_TYPE}"`);
  const book = { t: BOOK_TYPE, petnames: {}, records: {} };
  for (const [name, pub] of Object.entries(json.petnames ?? {})) {
    const n = name.toLowerCase();
    if (!PETNAME.test(n)) fail(`bad petname ${name}`);
    if (!isKwId(pub)) fail(`petname ${name} does not map to a kw-id`);
    book.petnames[n] = pub;
  }
  for (const [pub, entry] of Object.entries(json.records ?? {})) {
    if (!isKwId(pub)) fail(`records key ${pub} is not a kw-id`);
    if (typeof entry?.publisher !== 'string') fail(`records[${pub}].publisher missing`);
    const apps = {};
    for (const [slug, rec] of Object.entries(entry.apps ?? {})) {
      if (!SLUG.test(slug) || typeof rec !== 'string') fail(`bad app entry ${slug}`);
      apps[slug] = rec;
    }
    book.records[pub] = { publisher: entry.publisher, apps };
  }
  return book;
}

/** Make a book entry from signed bytes (tooling and tests). */
export function bookEntry(pdocBytes, apps) {
  return {
    publisher: base64url.encode(pdocBytes),
    apps: Object.fromEntries(Object.entries(apps).map(([slug, bytes]) => [slug, base64url.encode(bytes)])),
  };
}

export class LocalRail {
  /** @param {{ book?: object }} [options] */
  constructor({ book } = {}) {
    this.name = 'local';
    this.book = book ? parsePublisherBook(book) : { t: BOOK_TYPE, petnames: {}, records: {} };
  }

  async resolve({ publisher, slug, store }) {
    const label = publisher.toLowerCase();
    const pub = this.book.petnames[label] ?? store?.petname(label) ?? null;
    if (!pub) throw new RailError('UNKNOWN_ALIAS', `no petname "${publisher}" in the publisher book`, { rail: 'local' });
    const entry = this.book.records[pub];
    if (entry?.apps?.[slug]) {
      return {
        pdoc: base64url.decode(entry.publisher),
        rec: base64url.decode(entry.apps[slug]),
        railId: pub,
        via: 'publisher-book',
      };
    }
    const cached = store?.cachedRecords(pub, slug);
    if (cached) return { ...cached, railId: pub, via: 'trust-store' };
    throw new RailError('NOT_FOUND', `the publisher book has no record for ${slug} by ${publisher}`, { rail: 'local' });
  }

  labelFromRails() {
    return null; // petnames are per-user, never derived from a rail map
  }
}
