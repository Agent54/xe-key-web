// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// key-web URL grammar (Spec §1.3, §1.7.2):
//
//   key URL   key-web://<kw-id>.key/<path>             the ONLY origin form
//   name URL  key-web://<app-slug>.<publisher>[.<rail>]/<path>
//
// Rails: the last label `dht`, `nostr`, `local` or `key` selects that rail;
// otherwise the rail is `at` and everything after the slug is the ATProto
// handle (so `cool-site.alice.example` is slug `cool-site`, handle
// `alice.example`). `<slug>.<kw-id>.key` names an app under a
// self-certifying publisher key.
//
// Fragment directives `#:~:pin=<p>` (and, on name URLs, a whole-fragment
// `#pin=<p>`) are stripped before anything else sees the URL.

import { isKwId, MIN_PIN_LENGTH } from './ids.mjs';

export const SCHEME = 'key-web:';
export const RESERVED_RAILS = Object.freeze(['dht', 'nostr', 'local', 'key']);
export const ALL_RAILS = Object.freeze(['at', ...RESERVED_RAILS]);

const LDH = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const SLUG_MAX = 40;

export class KeyWebUrlError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'KeyWebUrlError';
    this.code = code;
  }
}

function splitFragment(fragment, isNameUrl) {
  // Returns { directives: Map, fragment: string-without-directives }.
  const directives = new Map();
  if (!fragment) return { directives, fragment: '' };
  let rest = fragment;
  const at = rest.indexOf(':~:');
  if (at >= 0) {
    const directiveText = rest.slice(at + 3);
    rest = rest.slice(0, at);
    for (const part of directiveText.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const key = eq < 0 ? part : part.slice(0, eq);
      const value = eq < 0 ? '' : decodeURIComponent(part.slice(eq + 1));
      // kw= hints use comma-separated sub-values; pin= is a single value.
      directives.set(key, value);
    }
  } else if (isNameUrl && /^pin=[a-z2-7]+$/.test(rest)) {
    // Hand-typed compatibility form: the WHOLE fragment is `pin=<value>`.
    directives.set('pin', rest.slice(4));
    rest = '';
  }
  return { directives, fragment: rest };
}

/**
 * Parse a key-web URL. Returns
 *   { kind: 'key', kwId, path, query, fragment, pin, directives }
 *   { kind: 'name', slug, publisher, rail, host, path, query, fragment, pin, directives }
 * Throws KeyWebUrlError for anything that is not a valid key-web URL.
 */
export function parseKeyWebUrl(input) {
  if (typeof input !== 'string') throw new KeyWebUrlError('BAD_URL', 'URL must be a string');
  const raw = input.trim().replace(/^web\+kw:/i, 'key-web:');
  const m = /^key-web:\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(raw);
  if (!m) throw new KeyWebUrlError('BAD_URL', `not a key-web:// URL: ${input}`);
  const authority = m[1];
  if (/[@:]/.test(authority)) {
    throw new KeyWebUrlError('BAD_URL', 'key-web URLs must not carry userinfo or a port');
  }
  // eslint-disable-next-line no-control-regex
  if (/[^\x21-\x7e]/.test(authority)) {
    throw new KeyWebUrlError('NOT_ASCII', 'key-web hosts are ASCII; xn-- labels stay punycode');
  }
  const host = authority.toLowerCase().replace(/\.$/, '');
  const labels = host.split('.');
  if (labels.some((l) => !l)) throw new KeyWebUrlError('BAD_HOST', `empty label in host ${host}`);
  const path = m[2] || '/';
  const query = m[3] ? m[3].slice(1) : '';
  const rawFragment = m[4] ? m[4].slice(1) : '';

  const last = labels[labels.length - 1];
  // key URL: exactly <kw-id>.key
  if (labels.length === 2 && last === 'key' && isKwId(labels[0])) {
    const { directives, fragment } = splitFragment(rawFragment, false);
    return finish({ kind: 'key', kwId: labels[0], host, path, query, fragment, directives });
  }
  // Bare kw-id typed as a host: rewritten to the canonical key URL.
  if (labels.length === 1 && isKwId(labels[0])) {
    const { directives, fragment } = splitFragment(rawFragment, false);
    return finish({ kind: 'key', kwId: labels[0], host: `${labels[0]}.key`, path, query, fragment, directives, rewrittenFromBareId: true });
  }

  if (labels.length < 2) throw new KeyWebUrlError('BAD_HOST', `name host needs <slug>.<publisher>: ${host}`);
  const [slug, ...rest] = labels;
  if (!LDH.test(slug) || slug.length > SLUG_MAX) {
    throw new KeyWebUrlError('BAD_SLUG', `app slug must be an LDH label of 1..${SLUG_MAX} chars: ${slug}`);
  }
  let rail = 'at';
  let publisherLabels = rest;
  if (RESERVED_RAILS.includes(last)) {
    rail = last;
    publisherLabels = rest.slice(0, -1);
  }
  if (publisherLabels.length === 0) throw new KeyWebUrlError('BAD_HOST', `missing publisher in ${host}`);
  for (const l of publisherLabels) {
    if (!LDH.test(l) && !(rail === 'nostr' && /^npub1[02-9ac-hj-np-z]{58}$/.test(l))) {
      throw new KeyWebUrlError('BAD_HOST', `invalid publisher label ${l}`);
    }
  }
  const publisher = publisherLabels.join('.');
  if (rail === 'at' && publisherLabels.length < 2) {
    throw new KeyWebUrlError('BAD_HOST', `ATProto handles need at least two labels: ${publisher}`);
  }
  if (rail === 'key' && (publisherLabels.length !== 1 || !isKwId(publisher))) {
    throw new KeyWebUrlError('BAD_HOST', `.key names must be <slug>.<kw-id>.key: ${host}`);
  }
  const { directives, fragment } = splitFragment(rawFragment, true);
  return finish({ kind: 'name', slug, publisher, rail, host, path, query, fragment, directives });
}

function finish(parsed) {
  const pin = parsed.directives.get('pin');
  if (pin !== undefined) {
    if (!/^[a-z2-7]+$/.test(pin)) throw new KeyWebUrlError('BAD_PIN', 'pin must be lowercase base32');
    if (pin.length < MIN_PIN_LENGTH) {
      throw new KeyWebUrlError('PIN_TOO_SHORT', `pins need at least ${MIN_PIN_LENGTH} characters (80 bits)`);
    }
  }
  return { ...parsed, pin: pin ?? null };
}

/** The canonical key URL for K_app, carrying path/query/fragment minus directives. */
export function canonicalKeyUrl(kwId, { path = '/', query = '', fragment = '' } = {}) {
  return `key-web://${kwId}.key${path || '/'}${query ? `?${query}` : ''}${fragment ? `#${fragment}` : ''}`;
}

/** Shareable human link with a pin (Spec §1.7.9). `.local` names are never shared. */
export function shareLink({ slug, publisher, rail }, kwId, pin) {
  if (rail === 'local') {
    return `key-web://${kwId}.key/#:~:pin=${pin}`;
  }
  const suffix = rail === 'at' ? '' : `.${rail}`;
  return `key-web://${slug}.${publisher}${suffix}/#:~:pin=${pin}`;
}
