// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The service worker of one key origin. It is the only thing that answers
// requests to http://<id>.localhost:<port>/, and it answers them from one
// place: the signed bundle stored for this origin, after verifying its
// Ed25519 signature and checking that the signing key is the one this
// origin's host name is made from.
//
// It verifies every time it starts, not once at install. So if anything on
// this origin, including the app itself, swaps the stored bytes, the origin
// stops serving instead of serving something unsigned.
//
// It never touches the network: its own policy is connect-src 'none', and
// there is no fetch() call in this file. Every response carries the Tier 0
// sandbox policy, whatever headers the bundle asked for.
//
// The module paths are the served ones (/__keyweb/engine/…); on disk the
// engine lives in runner/src/engine/.

import { responseFor, runnerOriginFrom } from './engine/policy.js';
import { verifySwbn } from './engine/swbn.js';

const ID = self.location.hostname.split('.')[0];
const RUNNER = runnerOriginFrom(self.location);
const REPORT_URI = `${RUNNER}/api/csp-report?o=${ID}`;
const CACHE_NAME = 'keyweb-bundle-v1';
const BUNDLE_URL = '/__keyweb/installed.swbn';

let state = null;
let loading = null;

async function load() {
  let next = null;
  try {
    const cache = await caches.open(CACHE_NAME);
    const stored = await cache.match(BUNDLE_URL);
    if (stored) {
      const report = await verifySwbn(new Uint8Array(await stored.arrayBuffer()), { expectedId: ID });
      next = { id: ID, sha256: report.sha256, exchanges: report.exchanges };
    }
  } catch {
    // Unverifiable bytes are the same as no bytes.
    next = null;
  }
  state = next;
  return state;
}

function ensure() {
  if (state) return Promise.resolve(state);
  if (!loading) {
    loading = load().finally(() => {
      loading = null;
    });
  }
  return loading;
}

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Only the loader page may ask for a boot, and each ask is good for one
// document, for a few seconds.
const LOADER_PATH = '/__keyweb/loader.html';
const ARMED_MS = 10000;
let armedUntil = 0;

self.addEventListener('message', (event) => {
  const port = event.ports[0];
  if (!port || event.data === null || typeof event.data !== 'object' || event.data.type !== 'activate') return;
  let fromLoader = false;
  try {
    fromLoader = new URL(event.source.url).pathname === LOADER_PATH;
  } catch {
    fromLoader = false;
  }
  if (!fromLoader) {
    port.postMessage({ ok: false });
    return;
  }
  event.waitUntil(load().then((loaded) => {
    armedUntil = loaded ? Date.now() + ARMED_MS : 0;
    port.postMessage(loaded ? { ok: true, sha256: loaded.sha256 } : { ok: false });
  }));
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // Another origin is not this worker's to answer: the page's policy decides.
  if (url.origin !== self.location.origin) return;
  // The loader comes from the browser, never from a bundle.
  if (url.pathname.startsWith('/__keyweb/')) return;
  const navigation = event.request.mode === 'navigate';
  const armed = navigation && Date.now() < armedUntil;
  if (navigation) armedUntil = 0;
  event.respondWith(ensure().then((current) => {
    const answer = responseFor(current, {
      method: event.request.method,
      pathname: url.pathname,
      destination: event.request.destination,
      navigation,
      armed,
      runnerOrigin: RUNNER,
      reportUri: REPORT_URI,
    });
    return new Response(event.request.method === 'HEAD' ? null : answer.body, { status: answer.status, headers: answer.headers });
  }));
});
