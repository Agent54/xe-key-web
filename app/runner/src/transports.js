// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The transports. Each one's whole job is to produce bytes. None of them is
// trusted: whatever comes back goes through the same verification, and the
// origin comes from the key that signed the bytes, never from where they
// were found.

import { MAX_BUNDLE_BYTES, PEER_COUNT } from './config.js';
import { SwarmError, checkManifest, swarmDownload } from './engine/chunks.js';

export class TransportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TransportError';
    this.code = code;
  }
}

const TIMEOUT_MS = 6000;

async function get(url, { timeout = TIMEOUT_MS } = {}) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeout);
  try {
    return await fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: abort.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function bytesOf(response) {
  const length = Number(response.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_BUNDLE_BYTES) throw new TransportError('TOO_LARGE', 'the server offers more bytes than a bundle may have');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAX_BUNDLE_BYTES) throw new TransportError('TOO_LARGE', 'more bytes than a bundle may have');
  return bytes;
}

/**
 * `net.simulatedOutage()` is true when the outage switch is on but there is
 * no control API to really close the sockets (the installed app has no dev
 * server): then the network transports refuse to try.
 */
export function makeTransports({ mirrorPort, cache, net }) {
  const mirrorBase = `http://localhost:${mirrorPort}`;
  const peerBase = (peer) => {
    const number = peer + 1;
    return `http://peer-${number}.localhost:${mirrorPort}`;
  };
  const guard = () => {
    if (net.simulatedOutage()) throw new TransportError('UNREACHABLE', 'the network is switched off');
  };

  return {
    mirrorUrl: (file) => `${mirrorBase}/mirrors/${file}`,

    /** One HTTP GET to an untrusted mirror. */
    async http(file) {
      guard();
      let response;
      try {
        response = await get(`${mirrorBase}/mirrors/${file}`);
      } catch {
        throw new TransportError('UNREACHABLE', 'the mirror did not answer (connection refused or timed out)');
      }
      if (!response.ok) throw new TransportError('NOT_FOUND', `the mirror answered ${response.status}`);
      return { bytes: await bytesOf(response), detail: `GET ${mirrorBase}/mirrors/${file}` };
    },

    /**
     * Asks the peers who has a bundle for this key, then pulls its chunks
     * from all of them at once, checking each chunk's hash.
     */
    async swarm(id, { poisonPeer = null, onEvent = () => {} } = {}) {
      guard();
      let manifest = null;
      let reachable = 0;
      for (let peer = 0; peer < PEER_COUNT && !manifest; peer++) {
        try {
          const response = await get(`${peerBase(peer)}/swarm/announce/${id}`, { timeout: 3000 });
          reachable += 1;
          if (response.ok) manifest = checkManifest(await response.json(), { maxBytes: MAX_BUNDLE_BYTES });
        } catch (error) {
          if (error instanceof SwarmError) throw new TransportError(error.code, error.message);
        }
      }
      if (!manifest) {
        if (reachable === 0) throw new TransportError('UNREACHABLE', `0 of ${PEER_COUNT} peers answered`);
        throw new TransportError('NOT_FOUND', 'no peer has a bundle for this key');
      }
      onEvent({ type: 'manifest', manifest });
      const fetchChunk = async (peer, hash) => {
        const response = await get(`${peerBase(peer)}/swarm/chunk/${hash}${poisonPeer === peer ? '?poison=1' : ''}`);
        if (!response.ok) throw new Error(`peer answered ${response.status}`);
        return new Uint8Array(await response.arrayBuffer());
      };
      try {
        const { bytes, stats } = await swarmDownload({ manifest, peers: PEER_COUNT, fetchChunk, onEvent });
        const shares = stats.perPeer.map((count, peer) => `peer ${peer + 1}: ${count}`).join(', ');
        const poisoned = stats.poisoned ? `; ${stats.poisoned} poisoned chunk${stats.poisoned === 1 ? '' : 's'} caught and re-fetched` : '';
        return { bytes, stats, detail: `${stats.chunks} chunks of ${manifest.chunkSize / 1024} KB (${shares})${poisoned}` };
      } catch (error) {
        if (error instanceof SwarmError) throw new TransportError(error.code, error.message);
        throw error;
      }
    },

    /**
     * Asks one resolver rail which key a name means. The answer is a signed
     * record, returned as it came: checking it is the caller's job.
     */
    async resolve(rail, publisher, app) {
      guard();
      let response;
      try {
        response = await get(`http://rail-${rail}.localhost:${mirrorPort}/resolve/${publisher}/${app}`, { timeout: 3000 });
      } catch {
        throw new TransportError('UNREACHABLE', `the .${rail} resolver did not answer`);
      }
      if (response.status === 404) throw new TransportError('NO_SUCH_NAME', `the .${rail} resolver has no record for this name`);
      if (!response.ok) throw new TransportError('RESOLVER_FAILED', `the .${rail} resolver answered ${response.status}`);
      try {
        return await response.json();
      } catch {
        throw new TransportError('RECORD_MALFORMED', `the .${rail} resolver did not answer with a record`);
      }
    },

    /** No network at all: the last bundle this runner verified for the key. */
    async offline(id) {
      const hit = await cache.latest(id);
      if (!hit) throw new TransportError('NOT_CACHED', 'no bundle for this key has been opened on this machine yet');
      return { bytes: hit.bytes, detail: `sha256 ${hit.meta.sha256.slice(0, 16)}… stored ${new Date(hit.meta.storedAt).toLocaleString('en-GB')}` };
    },
  };
}
