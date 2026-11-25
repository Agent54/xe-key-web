// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Pins: which key each human-readable name meant the first time it was
// used on this machine.
//
// A resolver rail can be wrong, or taken over. So the first key a name
// resolves to is pinned, and from then on the pin is the authority and the
// rail is only a hint. A rail that later answers with a different key is
// not believed. The one thing that can move a pin is a rotation
// certificate signed by the pinned key for a successor it committed to in
// advance, which is the key's own decision, not the rail's.
//
// This is trust on first use, and it has the usual limit: it protects a
// name from the second time on. The first answer is taken as given.
//
// Pure bookkeeping over a {load, save} store, so it is tested without a
// browser.

import { parseAddress } from './engine/names.js';
import { isKeyId } from './engine/swbn.js';

/**
 * How a key a rail just answered with relates to the pin for that name:
 *   first-use   there is no pin yet
 *   match       it is the pinned key
 *   stale       it is a key this pin has already rotated away from
 *   mismatch    it is some other key: a hijack unless a rotation proves otherwise
 */
export function judgeRecord(pin, key) {
  if (!pin) return 'first-use';
  if (pin.key === key) return 'match';
  if (Array.isArray(pin.previous) && pin.previous.includes(key)) return 'stale';
  return 'mismatch';
}

export class PinBook {
  constructor(store) {
    this.store = store;
    this.pins = {};
    const loaded = store.load();
    if (loaded && typeof loaded === 'object' && !Array.isArray(loaded)) {
      for (const [name, pin] of Object.entries(loaded)) {
        const parsed = parseAddress(name);
        if (!parsed || parsed.kind !== 'name' || parsed.host !== name || !pin || !isKeyId(pin.key)) continue;
        this.pins[name] = {
          key: pin.key,
          publisherKey: typeof pin.publisherKey === 'string' ? pin.publisherKey : null,
          pinnedAt: Number(pin.pinnedAt) || 0,
          seenAt: Number(pin.seenAt) || 0,
          previous: Array.isArray(pin.previous) ? pin.previous.filter(isKeyId) : [],
        };
      }
    }
  }

  save() {
    this.store.save(this.pins);
  }

  get(name) {
    return Object.hasOwn(this.pins, name) ? this.pins[name] : null;
  }

  list() {
    return Object.entries(this.pins).map(([name, pin]) => ({ name, ...pin })).sort((a, b) => (a.name < b.name ? -1 : 1));
  }

  /** Every pinned name that currently means this key. */
  namesFor(key) {
    return this.list().filter((pin) => pin.key === key).map((pin) => pin.name);
  }

  /** Pins a name on first use. An existing pin is never overwritten this way. */
  pin(name, { key, publisherKey = null }, now = Date.now()) {
    const parsed = parseAddress(name);
    if (!parsed || parsed.kind !== 'name' || parsed.host !== name) throw new Error('only a name on a resolver rail can be pinned');
    if (!isKeyId(key)) throw new Error('a pin needs a key');
    if (this.get(name)) throw new Error('this name is already pinned');
    this.pins[name] = { key, publisherKey, pinnedAt: now, seenAt: now, previous: [] };
    this.save();
    return this.pins[name];
  }

  /** Notes that a rail confirmed the pin. */
  seen(name, now = Date.now()) {
    const pin = this.get(name);
    if (!pin) return;
    pin.seenAt = now;
    this.save();
  }

  /**
   * Moves a pin to the successor of its key. The caller must have verified
   * the rotation; this only records it, and remembers the old key so that a
   * rail still serving it is recognised as out of date, not hostile.
   */
  follow(name, toKey, { publisherKey = null } = {}, now = Date.now()) {
    const pin = this.get(name);
    if (!pin || !isKeyId(toKey) || pin.key === toKey) return false;
    pin.previous = [...pin.previous.filter((key) => key !== toKey), pin.key];
    pin.key = toKey;
    if (publisherKey) pin.publisherKey = publisherKey;
    pin.seenAt = now;
    this.save();
    return true;
  }

  /** Forgets a name. The next key it resolves to will be pinned as if for the first time. */
  unpin(name) {
    if (!this.get(name)) return false;
    delete this.pins[name];
    this.save();
    return true;
  }
}
