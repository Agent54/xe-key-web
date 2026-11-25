// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Petnames and accepted key rotations.
//
// A signature proves which key published a bundle. It says nothing about
// who that is: anyone can sign an app that calls itself "LocalPad". A
// petname is the missing half. It is a name the person chose, bound on
// their own machine to one key, and it is the only name the runner shows as
// trusted. A bundle's own name is shown as a claim, and if that claim
// collides with a petname bound to a different key, it is shown as an
// impersonation attempt.
//
// Both books keep their state through a tiny {load, save} store, so they
// can be tested without a browser.

import { isKeyId } from './engine/swbn.js';

/** The form a name is shown in: trimmed, single spaces, no control characters, at most 40 characters. */
export function cleanName(name) {
  if (typeof name !== 'string') return '';
  return name.normalize('NFKC').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').replace(/\s+/g, ' ').trim().slice(0, 40);
}

/**
 * The form two names are compared in: compatibility-folded, lower case,
 * letters and digits only. "LocalPad", "local pad" and "Local-Pad" are one name.
 */
export function nameKey(name) {
  return cleanName(name).toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
}

/**
 * A petname as the first label of a key-web://<label>.local/ address:
 * lower case, hyphens for everything else. "Trusted Notes" is
 * "trusted-notes". Returns null for a name with nothing to make a label of.
 */
export function petnameLabel(name) {
  const label = cleanName(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32).replace(/-+$/, '');
  return label === '' ? null : label;
}

export class PetnameBook {
  constructor(store) {
    this.store = store;
    const loaded = store.load();
    this.entries = Array.isArray(loaded)
      ? loaded.filter((entry) => entry && typeof entry.name === 'string' && isKeyId(entry.id) && nameKey(entry.name) !== '')
      : [];
  }

  save() {
    this.store.save(this.entries);
  }

  list() {
    return this.entries.slice();
  }

  nameFor(id) {
    const entry = this.entries.find((candidate) => candidate.id === id);
    return entry ? entry.name : null;
  }

  entryForName(name) {
    const key = nameKey(name);
    return key === '' ? null : this.entries.find((candidate) => nameKey(candidate.name) === key) || null;
  }

  /**
   * Binds a petname to a key. A name already bound to another key is a
   * collision and changes nothing. A key that already has a petname is
   * renamed.
   */
  bind(name, id, now = Date.now()) {
    const shown = cleanName(name);
    if (nameKey(shown) === '') return { ok: false, code: 'EMPTY_NAME' };
    if (!isKeyId(id)) return { ok: false, code: 'BAD_KEY' };
    const holder = this.entryForName(shown);
    if (holder && holder.id !== id) return { ok: false, code: 'COLLISION', existing: { ...holder } };
    const entry = { name: shown, id, boundAt: now, note: '' };
    this.entries = this.entries.filter((candidate) => candidate.id !== id);
    this.entries.push(entry);
    this.save();
    return { ok: true, entry };
  }

  unbind(id) {
    const before = this.entries.length;
    this.entries = this.entries.filter((candidate) => candidate.id !== id);
    if (this.entries.length !== before) this.save();
    return this.entries.length !== before;
  }

  /** After an accepted rotation the petname follows the origin to its new key. */
  follow(fromId, toId, note) {
    const entry = this.entries.find((candidate) => candidate.id === fromId);
    if (!entry || !isKeyId(toId)) return false;
    this.entries = this.entries.filter((candidate) => candidate.id !== toId && candidate.id !== fromId);
    this.entries.push({ ...entry, id: toId, note });
    this.save();
    return true;
  }

  /**
   * How to present a verified bundle that claims `claimed` as its name:
   *   petname    this key has a petname: show it
   *   impostor   the claimed name is someone's petname, bound to another key
   *   unnamed    no petname and no collision: show the claim as a claim
   */
  judge(claimed, id) {
    const own = this.nameFor(id);
    if (own) return { status: 'petname', name: own };
    const holder = claimed ? this.entryForName(claimed) : null;
    if (holder && holder.id !== id) return { status: 'impostor', name: cleanName(claimed), boundTo: holder.id, petname: holder.name };
    return { status: 'unnamed', name: cleanName(claimed || '') };
  }
}

export class RotationBook {
  constructor(store) {
    this.store = store;
    const loaded = store.load();
    this.records = {};
    if (loaded && typeof loaded === 'object' && !Array.isArray(loaded)) {
      for (const [from, record] of Object.entries(loaded)) {
        if (isKeyId(from) && record && isKeyId(record.to) && Number.isSafeInteger(record.sequence)) this.records[from] = record;
      }
    }
  }

  save() {
    this.store.save(this.records);
  }

  /** The record of the rotation away from this key, or null. */
  recordFor(id) {
    return Object.hasOwn(this.records, id) ? this.records[id] : null;
  }

  /** Remembers an accepted rotation with everything needed to check it again later. */
  accept(fromId, { to, sequence, certificate, committedDigest }, now = Date.now()) {
    this.records[fromId] = { to, sequence, certificate, committedDigest, acceptedAt: now };
    this.save();
  }

  /** Follows accepted rotations from a key to the key that holds the origin now. */
  resolve(id) {
    const hops = [];
    const seen = new Set([id]);
    let current = id;
    for (let record = this.recordFor(current); record && !seen.has(record.to); record = this.recordFor(current)) {
      hops.push({ from: current, to: record.to, sequence: record.sequence });
      seen.add(record.to);
      current = record.to;
    }
    return { id: current, hops };
  }

  /**
   * The sequence a new rotation of this key must follow. A key that was
   * already rotated away from reports that rotation, so the same
   * certificate cannot be played twice; a key that was rotated to reports
   * the rotation that made it current; a key with no history reports 0.
   */
  sequenceFor(id) {
    const away = this.recordFor(id);
    if (away) return away.sequence;
    const into = Object.values(this.records).find((record) => record.to === id);
    return into ? into.sequence : 0;
  }

  reset() {
    this.records = {};
    this.save();
  }
}
