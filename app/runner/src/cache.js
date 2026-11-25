// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The runner's own bundle cache: content-addressed, and trusted for nothing.
// A bundle is stored under its SHA-256 after it verified. When it is read
// back, the bytes are hashed again, and the caller verifies the signature
// again as if they had come off the network. A cache that was tampered with
// is just another transport that failed.

import { sha256Hex } from './engine/bytes.js';

const CACHE_NAME = 'keyweb-cas-v1';
const INDEX_KEY = 'keyweb.cas.index';

/** A JSON value in localStorage that never throws. */
export function jsonStore(key, fallback) {
  return {
    load() {
      try {
        const raw = localStorage.getItem(key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch {
        return fallback;
      }
    },
    save(value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
      } catch {
        // Storage is full or blocked: the app still works, it just forgets.
      }
    },
  };
}

export function bundleCache() {
  const index = jsonStore(INDEX_KEY, {});
  const memory = new Map();
  const hasCaches = typeof caches === 'object';
  const urlFor = (hash) => `/cas/${hash}`;

  const readIndex = () => {
    const value = index.load();
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  };

  return {
    /** Stores verified bytes under their hash and remembers them as the latest for their key. */
    async put(report, bytes, meta = {}) {
      if (hasCaches) {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(urlFor(report.sha256), new Response(bytes.slice(), { headers: { 'Content-Type': 'application/octet-stream' } }));
      } else memory.set(report.sha256, bytes.slice());
      const entries = readIndex();
      entries[report.id] = { sha256: report.sha256, size: bytes.length, storedAt: Date.now(), name: meta.name || null, version: meta.version || null, via: meta.via || null };
      index.save(entries);
    },

    /** The latest bytes stored for a key, or null. A hash mismatch evicts the entry. */
    async latest(id) {
      const entries = readIndex();
      const entry = Object.hasOwn(entries, id) ? entries[id] : null;
      if (!entry || typeof entry.sha256 !== 'string') return null;
      let bytes = null;
      if (hasCaches) {
        const cache = await caches.open(CACHE_NAME);
        const stored = await cache.match(urlFor(entry.sha256));
        if (stored) bytes = new Uint8Array(await stored.arrayBuffer());
      } else if (memory.has(entry.sha256)) bytes = memory.get(entry.sha256).slice();
      if (!bytes || (await sha256Hex(bytes)) !== entry.sha256) {
        delete entries[id];
        index.save(entries);
        return null;
      }
      return { bytes, meta: entry };
    },

    list() {
      return Object.entries(readIndex()).map(([id, entry]) => ({ id, ...entry }));
    },

    async clear() {
      memory.clear();
      if (hasCaches) await caches.delete(CACHE_NAME);
      index.save({});
    },
  };
}
