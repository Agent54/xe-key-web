// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The numbers the page, the dev server, the packager and the tests agree on.

/** The runner page, and every key origin (http://<id>.localhost:APP_PORT). */
export const APP_PORT = 5760;
/** "The network": the HTTP mirror, the four swarm peers, the relay and the tracker. */
export const MIRROR_PORT = 5761;

export const PEER_COUNT = 4;
export const CHUNK_SIZE = 16 * 1024;

/** A signed bundle larger than this is refused before anything is parsed. */
export const MAX_BUNDLE_BYTES = 32 * 1024 * 1024;

/** What one relay message may carry under the net:sync-relay capability. */
export const MAX_RELAY_BYTES = 64 * 1024;

export const TIMED_GRANT_MS = 5 * 60 * 1000;
