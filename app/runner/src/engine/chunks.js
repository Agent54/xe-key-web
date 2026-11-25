// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Content-addressed chunks for the swarm transport. A file is cut into
// fixed-size chunks, each named by its SHA-256. A peer is never trusted:
// every chunk is hashed as it arrives, a chunk that does not match its name
// is thrown away and fetched from another peer, and the reassembled file
// must hash to the manifest's total. The Ed25519 signature is still checked
// afterwards, by the same engine as for every other transport, so even a
// lying manifest can only waste time.

import { concat, hex, sha256 } from './bytes.js';

const HASH = /^[0-9a-f]{64}$/;

export class SwarmError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'SwarmError';
    this.code = code;
  }
}

/** Cuts bytes into chunks and names each one. Resolves with {size, chunkSize, sha256, chunks: [hash]}. */
export async function chunkManifest(bytes, chunkSize, subtle) {
  if (!Number.isInteger(chunkSize) || chunkSize < 1) throw new Error('chunk size must be a positive integer');
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    chunks.push(hex(await sha256(bytes.subarray(offset, Math.min(bytes.length, offset + chunkSize)), subtle)));
  }
  return { size: bytes.length, chunkSize, sha256: hex(await sha256(bytes, subtle)), chunks };
}

/** Throws unless a manifest from a peer is internally consistent and within limits. */
export function checkManifest(manifest, { maxBytes }) {
  if (manifest === null || typeof manifest !== 'object') throw new SwarmError('MANIFEST_MALFORMED', 'the manifest is not an object');
  const { size, chunkSize, chunks } = manifest;
  if (!Number.isSafeInteger(size) || size < 1 || size > maxBytes) throw new SwarmError('MANIFEST_MALFORMED', 'the manifest size is out of range');
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1024 || chunkSize > 1024 * 1024) throw new SwarmError('MANIFEST_MALFORMED', 'the chunk size is out of range');
  if (typeof manifest.sha256 !== 'string' || !HASH.test(manifest.sha256)) throw new SwarmError('MANIFEST_MALFORMED', 'the manifest total hash is malformed');
  if (!Array.isArray(chunks) || chunks.length !== Math.ceil(size / chunkSize) || !chunks.every((hash) => typeof hash === 'string' && HASH.test(hash))) {
    throw new SwarmError('MANIFEST_MALFORMED', 'the chunk list does not match the size');
  }
  return manifest;
}

/**
 * Downloads every chunk of a manifest from a set of peers.
 *
 *   peers        how many peers there are (numbered from 0)
 *   fetchChunk   async (peer, hash, index) => Uint8Array, may throw
 *   onEvent      called with {type: 'chunk', index, peer, status, ms, bytes}
 *                where status is 'ok', 'poisoned' (wrong hash) or 'failed' (no answer)
 *
 * Chunk i is asked of peer i mod peers first, then of each next peer in
 * turn. A peer that serves one bad chunk is not asked again. Resolves with
 * {bytes, stats: {chunks, poisoned, failed, perPeer, banned}}.
 */
export async function swarmDownload({ manifest, peers, fetchChunk, onEvent = () => {}, concurrency = 4, subtle, now = () => Date.now() }) {
  const parts = new Array(manifest.chunks.length);
  const banned = new Set();
  const stats = { chunks: manifest.chunks.length, poisoned: 0, failed: 0, perPeer: new Array(peers).fill(0), banned: [] };

  const fetchOne = async (index) => {
    const hash = manifest.chunks[index];
    const expected = index === manifest.chunks.length - 1 ? manifest.size - manifest.chunkSize * index : manifest.chunkSize;
    for (let turn = 0; turn < peers; turn++) {
      const peer = (index + turn) % peers;
      if (banned.has(peer)) continue;
      const started = now();
      let bytes;
      try {
        bytes = await fetchChunk(peer, hash, index);
      } catch {
        stats.failed += 1;
        onEvent({ type: 'chunk', index, peer, status: 'failed', ms: now() - started, bytes: 0 });
        continue;
      }
      const good = bytes instanceof Uint8Array && bytes.length === expected && hex(await sha256(bytes, subtle)) === hash;
      if (!good) {
        stats.poisoned += 1;
        if (!banned.has(peer)) {
          banned.add(peer);
          stats.banned.push(peer);
        }
        onEvent({ type: 'chunk', index, peer, status: 'poisoned', ms: now() - started, bytes: bytes instanceof Uint8Array ? bytes.length : 0 });
        continue;
      }
      parts[index] = bytes;
      stats.perPeer[peer] += 1;
      onEvent({ type: 'chunk', index, peer, status: 'ok', ms: now() - started, bytes: bytes.length });
      return;
    }
    throw new SwarmError('CHUNK_UNAVAILABLE', `no peer could deliver chunk ${index}`);
  };

  let next = 0;
  const worker = async () => {
    while (next < parts.length) await fetchOne(next++);
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, parts.length)) }, worker));

  const bytes = concat(parts);
  if (bytes.length !== manifest.size || hex(await sha256(bytes, subtle)) !== manifest.sha256) {
    throw new SwarmError('ASSEMBLY_MISMATCH', 'the reassembled file does not match the manifest');
  }
  return { bytes, stats };
}
