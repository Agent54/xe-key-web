// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Capability escalation, least privilege first. An app starts in Tier 0
// with no way to reach anything. To do more it has to:
//
//   1. have declared the capability in its signed descriptor,
//   2. ask for it by name, and
//   3. be granted it by the person, once or for five minutes.
//
// A grant never loosens the app's sandbox. The app's policy stays
// connect-src 'none'; the runner performs the one narrow operation on the
// app's behalf and hands back the result. What is granted is an operation,
// not a network.
//
// This file is pure bookkeeping, so it can be tested without a browser.

import { MAX_RELAY_BYTES, TIMED_GRANT_MS } from './config.js';

/** Every capability this runner knows how to broker. Anything else is refused unseen. */
export const CAPABILITIES = Object.freeze({
  'net:sync-relay': Object.freeze({
    title: 'Sync through the relay',
    grants: 'Store and fetch its own sync data at one address: its own slot on the sync relay.',
    limits: Object.freeze([
      'One endpoint only, chosen by the runner, never by the app',
      `At most ${MAX_RELAY_BYTES / 1024} KB per message, as plain text`,
      'No other host, no cookies, no headers of its choosing',
    ]),
  }),
  'storage:export': Object.freeze({
    title: 'Save a file',
    grants: 'Hand the runner one text file to save into your downloads.',
    limits: Object.freeze([
      'The runner writes the file; the app never sees your disk',
      'Text only, at most 1 MB, with a plain file name',
    ]),
  }),
});

export const GRANT_MODES = Object.freeze(['once', 'timed']);

const keyOf = (id, capability) => `${id}\n${capability}`;

export class GrantBook {
  constructor({ now = () => Date.now(), timedMs = TIMED_GRANT_MS } = {}) {
    this.now = now;
    this.timedMs = timedMs;
    this.grants = new Map();
  }

  /**
   * Whether a request may even be shown to the person. `declared` is the
   * capability list from the app's verified, signed descriptor.
   */
  screen(capability, declared) {
    if (typeof capability !== 'string' || !Object.hasOwn(CAPABILITIES, capability)) return { ok: false, code: 'UNKNOWN_CAPABILITY' };
    if (!Array.isArray(declared) || !declared.includes(capability)) return { ok: false, code: 'UNDECLARED_CAPABILITY' };
    return { ok: true };
  }

  grant(id, capability, mode) {
    if (!Object.hasOwn(CAPABILITIES, capability)) throw new Error('unknown capability');
    if (!GRANT_MODES.includes(mode)) throw new Error('unknown grant mode');
    const at = this.now();
    const grant = { id, capability, mode, grantedAt: at, expires: mode === 'timed' ? at + this.timedMs : null, uses: 0 };
    this.grants.set(keyOf(id, capability), grant);
    return grant;
  }

  /** The live grant for this app and capability, or the reason there is none. Does not consume it. */
  check(id, capability) {
    const grant = this.grants.get(keyOf(id, capability));
    if (!grant) return { ok: false, code: 'CAPABILITY_NOT_GRANTED' };
    if (grant.mode === 'timed' && this.now() >= grant.expires) {
      this.grants.delete(keyOf(id, capability));
      return { ok: false, code: 'GRANT_EXPIRED' };
    }
    return { ok: true, grant };
  }

  /** Spends the grant on one operation. A "once" grant is gone afterwards, whatever the operation does. */
  use(id, capability) {
    const result = this.check(id, capability);
    if (!result.ok) return result;
    result.grant.uses += 1;
    if (result.grant.mode === 'once') this.grants.delete(keyOf(id, capability));
    return result;
  }

  revoke(id, capability) {
    return this.grants.delete(keyOf(id, capability));
  }

  revokeAll(id) {
    for (const [key, grant] of this.grants) if (grant.id === id) this.grants.delete(key);
  }

  /** Live grants, for one app or for all. Expired ones are dropped. */
  list(id = null) {
    const out = [];
    for (const [key, grant] of this.grants) {
      if (grant.mode === 'timed' && this.now() >= grant.expires) this.grants.delete(key);
      else if (id === null || grant.id === id) out.push(grant);
    }
    return out;
  }
}

/** Checks the arguments of a brokered operation before anything is sent anywhere. */
export function checkArguments(capability, args) {
  if (args === null || typeof args !== 'object') return { ok: false, code: 'BAD_ARGUMENT' };
  if (capability === 'net:sync-relay') {
    if (args.op === 'pull') return { ok: true, op: 'pull' };
    if (args.op !== 'push' || typeof args.data !== 'string') return { ok: false, code: 'BAD_ARGUMENT' };
    if (new TextEncoder().encode(args.data).length > MAX_RELAY_BYTES) return { ok: false, code: 'TOO_LARGE' };
    return { ok: true, op: 'push', data: args.data };
  }
  if (capability === 'storage:export') {
    if (typeof args.text !== 'string' || args.text.length > 1024 * 1024) return { ok: false, code: 'BAD_ARGUMENT' };
    const name = typeof args.filename === 'string' ? args.filename.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 64) : '';
    return { ok: true, filename: name || 'export.txt', text: args.text };
  }
  return { ok: false, code: 'UNKNOWN_CAPABILITY' };
}
