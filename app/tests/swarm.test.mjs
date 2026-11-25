// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Content-addressed chunks and the multi-peer download.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import { SwarmError, checkManifest, chunkManifest, swarmDownload } from '../runner/src/engine/chunks.js';

const CHUNK = 16 * 1024;
const LIMIT = { maxBytes: 32 * 1024 * 1024 };
/** Random bytes of any size (getRandomValues fills at most 64 KB at a time). */
function file(size) {
  const out = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) crypto.getRandomValues(out.subarray(offset, Math.min(size, offset + 65536)));
  return out;
}

/** Peers that all hold the file. `misbehave(peer, hash, index)` may return other bytes or throw. */
function peersFor(bytes, manifest, misbehave = () => undefined) {
  const asked = [];
  const fetchChunk = async (peer, hash, index) => {
    asked.push({ peer, index });
    const bad = misbehave(peer, hash, index);
    if (bad !== undefined) return bad;
    return bytes.slice(index * manifest.chunkSize, Math.min(bytes.length, (index + 1) * manifest.chunkSize));
  };
  return { fetchChunk, asked };
}

describe('chunk manifests', () => {
  test('name every chunk by its SHA-256 and the whole file too', async () => {
    const bytes = file(CHUNK * 3 + 100);
    const manifest = await chunkManifest(bytes, CHUNK);
    assert.equal(manifest.size, bytes.length);
    assert.equal(manifest.chunks.length, 4);
    assert.equal(manifest.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(manifest.chunks[3], createHash('sha256').update(bytes.subarray(CHUNK * 3)).digest('hex'));
    assert.equal((await chunkManifest(file(CHUNK), CHUNK)).chunks.length, 1);
    assert.equal((await chunkManifest(file(CHUNK + 1), CHUNK)).chunks.length, 2);
    await assert.rejects(chunkManifest(bytes, 0), /chunk size/);
  });

  test('from a peer are checked before a single chunk is asked for', async () => {
    const good = await chunkManifest(file(CHUNK * 2), CHUNK);
    assert.equal(checkManifest(good, LIMIT), good);
    const bad = [
      null, 'x', { ...good, size: 0 }, { ...good, size: LIMIT.maxBytes + 1 }, { ...good, size: 1.5 }, { ...good, chunkSize: 10 },
      { ...good, chunkSize: 64 * 1024 * 1024 }, { ...good, sha256: 'xyz' }, { ...good, chunks: good.chunks.slice(1) },
      { ...good, chunks: [...good.chunks, good.chunks[0]] }, { ...good, chunks: ['00', '11'] }, { ...good, chunks: 'none' },
    ];
    for (const manifest of bad) assert.throws(() => checkManifest(manifest, LIMIT), (error) => error instanceof SwarmError && error.code === 'MANIFEST_MALFORMED');
  });
});

describe('the swarm download', () => {
  test('spreads chunks across four peers and reassembles the exact file', async () => {
    const bytes = file(CHUNK * 9 + 5);
    const manifest = await chunkManifest(bytes, CHUNK);
    const { fetchChunk } = peersFor(bytes, manifest);
    const events = [];
    const { bytes: got, stats } = await swarmDownload({ manifest, peers: 4, fetchChunk, onEvent: (event) => events.push(event) });
    assert.deepEqual([...got], [...bytes]);
    assert.deepEqual(stats.perPeer, [3, 3, 2, 2]);
    assert.equal(stats.poisoned, 0);
    assert.equal(events.filter((event) => event.status === 'ok').length, 10);
  });

  test('catches a poisoned chunk by its hash, drops that peer, and gets the chunk from the next one', async () => {
    const bytes = file(CHUNK * 8);
    const manifest = await chunkManifest(bytes, CHUNK);
    // Peer #2 (index 1) answers with the right length and the wrong bytes.
    const { fetchChunk, asked } = peersFor(bytes, manifest, (peer, hash, index) => {
      if (peer !== 1) return undefined;
      const chunk = bytes.slice(index * CHUNK, (index + 1) * CHUNK);
      chunk[0] ^= 0xff;
      return chunk;
    });
    const events = [];
    const { bytes: got, stats } = await swarmDownload({ manifest, peers: 4, fetchChunk, onEvent: (event) => events.push(event), concurrency: 1 });
    assert.deepEqual([...got], [...bytes]);
    assert.equal(stats.poisoned, 1);
    assert.deepEqual(stats.banned, [1]);
    assert.equal(stats.perPeer[1], 0);
    const poisoned = events.find((event) => event.status === 'poisoned');
    assert.deepEqual({ index: poisoned.index, peer: poisoned.peer }, { index: 1, peer: 1 });
    // The very next event for that chunk is the good copy from peer #3.
    const rescue = events[events.indexOf(poisoned) + 1];
    assert.deepEqual({ index: rescue.index, peer: rescue.peer, status: rescue.status }, { index: 1, peer: 2, status: 'ok' });
    // Once caught lying, peer #2 is never asked again.
    assert.equal(asked.filter((ask) => ask.peer === 1).length, 1);
  });

  test('treats a wrong-length answer and a non-answer as bad too', async () => {
    const bytes = file(CHUNK * 4);
    const manifest = await chunkManifest(bytes, CHUNK);
    const short = peersFor(bytes, manifest, (peer) => (peer === 0 ? new Uint8Array(10) : undefined));
    assert.deepEqual([...(await swarmDownload({ manifest, peers: 4, fetchChunk: short.fetchChunk })).bytes], [...bytes]);
    const text = peersFor(bytes, manifest, (peer) => (peer === 2 ? 'not bytes' : undefined));
    assert.deepEqual((await swarmDownload({ manifest, peers: 4, fetchChunk: text.fetchChunk })).stats.banned, [2]);
  });

  test('routes around peers that are down', async () => {
    const bytes = file(CHUNK * 6);
    const manifest = await chunkManifest(bytes, CHUNK);
    const { fetchChunk } = peersFor(bytes, manifest, (peer) => {
      if (peer === 0 || peer === 3) throw new Error('connection refused');
      return undefined;
    });
    const { bytes: got, stats } = await swarmDownload({ manifest, peers: 4, fetchChunk });
    assert.deepEqual([...got], [...bytes]);
    assert.ok(stats.failed >= 2);
    assert.equal(stats.perPeer[0] + stats.perPeer[3], 0);
    assert.equal(stats.poisoned, 0);
  });

  test('fails closed when no honest peer has a chunk', async () => {
    const bytes = file(CHUNK * 3);
    const manifest = await chunkManifest(bytes, CHUNK);
    const liars = peersFor(bytes, manifest, () => new Uint8Array(CHUNK));
    await assert.rejects(swarmDownload({ manifest, peers: 4, fetchChunk: liars.fetchChunk }), (error) => error instanceof SwarmError && error.code === 'CHUNK_UNAVAILABLE');
    const dead = peersFor(bytes, manifest, () => {
      throw new Error('down');
    });
    await assert.rejects(swarmDownload({ manifest, peers: 4, fetchChunk: dead.fetchChunk }), (error) => error.code === 'CHUNK_UNAVAILABLE');
  });

  test('a manifest that lies about the total is caught after assembly', async () => {
    const bytes = file(CHUNK * 2);
    const manifest = { ...(await chunkManifest(bytes, CHUNK)), sha256: '0'.repeat(64) };
    const { fetchChunk } = peersFor(bytes, manifest);
    await assert.rejects(swarmDownload({ manifest, peers: 4, fetchChunk }), (error) => error.code === 'ASSEMBLY_MISMATCH');
  });
});
