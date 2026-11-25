// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The key-origin loader. The dev server serves this page, and only this
// page, at http://<id>.localhost:<port>/__keyweb/loader.html. It stands in
// for what a browser's own key-web:// scheme handler would do:
//
//   1. take the bundle bytes the runner hands over,
//   2. verify them again, here, and insist that the key that signed them is
//      the key this origin's host name is made from,
//   3. store them, and start the service worker that serves this origin out
//      of them and nothing else.
//
// It trusts no one for that. The runner already verified the bytes; this
// page does not take its word, and the service worker does not take this
// page's word either: it verifies what is stored every time it starts.
//
// The module paths below are the served ones (/__keyweb/engine/…); on disk
// the engine lives in runner/src/engine/.

import { LOADER_POLICY_NAME, runnerOriginFrom } from './engine/policy.js';
import { VerifyError, isKeyId, verifySwbn } from './engine/swbn.js';

const RUNNER = runnerOriginFrom(location);
const ID = location.hostname.split('.')[0];
const CACHE_NAME = 'keyweb-bundle-v1';
const BUNDLE_URL = '/__keyweb/installed.swbn';
const WORKER_URL = '/__keyweb/sw.js';
const MAX_ENTRIES = 512;
const MAX_VALUE = 1024 * 1024;

const detail = document.getElementById('detail');
const say = (text) => {
  detail.textContent = text;
};
const framed = window.parent !== window;
const post = (message) => {
  if (framed) window.parent.postMessage({ keyweb: 1, ...message }, RUNNER);
};

class LoaderError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function storageWorks() {
  try {
    const probe = '__keyweb_probe__';
    localStorage.setItem(probe, '1');
    localStorage.removeItem(probe);
    return typeof caches === 'object' && 'serviceWorker' in navigator;
  } catch {
    return false;
  }
}

// Registering a worker is a script-URL sink, and this page requires Trusted
// Types. This is the project's one policy. Whatever it is asked for, it
// answers with the worker's fixed, same-origin URL.
const workerUrl = globalThis.trustedTypes
  ? trustedTypes.createPolicy(LOADER_POLICY_NAME, { createScriptURL: () => WORKER_URL }).createScriptURL(WORKER_URL)
  : WORKER_URL;

async function startWorker() {
  await navigator.serviceWorker.register(workerUrl, { scope: '/', type: 'module', updateViaCache: 'none' });
  const registration = await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((done, fail) => {
      const timer = setTimeout(() => fail(new LoaderError('WORKER_NOT_IN_CONTROL', 'the service worker did not take control of this origin')), 5000);
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        clearTimeout(timer);
        done();
      }, { once: true });
    });
  }
  return registration.active;
}

function askWorker(worker, message) {
  return new Promise((done, fail) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => fail(new LoaderError('WORKER_SILENT', 'the service worker did not answer')), 8000);
    channel.port1.onmessage = (event) => {
      clearTimeout(timer);
      done(event.data);
    };
    worker.postMessage(message, [channel.port2]);
  });
}

async function install(buffer) {
  if (!(buffer instanceof ArrayBuffer)) throw new LoaderError('BAD_MESSAGE', 'no bundle bytes were sent');
  const bytes = new Uint8Array(buffer);
  say('Checking the Ed25519 signature.');
  const report = await verifySwbn(bytes, { expectedId: ID });

  say('Storing the verified bundle.');
  const cache = await caches.open(CACHE_NAME);
  await cache.put(BUNDLE_URL, new Response(bytes, { headers: { 'Content-Type': 'application/octet-stream', 'X-Key-Web-Sha256': report.sha256 } }));

  say('Starting the sandbox.');
  const worker = await startWorker();
  const answer = await askWorker(worker, { type: 'activate' });
  if (!answer || answer.ok !== true || answer.sha256 !== report.sha256) throw new LoaderError('WORKER_REJECTED', 'the service worker did not accept the stored bundle');

  // Prove the worker, not the server, now answers for this origin.
  const probe = await fetch('/', { method: 'HEAD', cache: 'no-store' });
  if (probe.headers.get('X-Key-Web-Origin') !== `key-web://${ID}/`) throw new LoaderError('WORKER_NOT_IN_CONTROL', 'requests to this origin are not being served from the bundle');
  return report;
}

function exportStorage() {
  const entries = [];
  let bytes = 0;
  for (let i = 0; i < localStorage.length && entries.length < MAX_ENTRIES; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);
    entries.push([key, value]);
    bytes += key.length + value.length;
  }
  return { entries, bytes };
}

function importStorage(entries, overwrite) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) throw new LoaderError('BAD_MESSAGE', 'the entries are malformed');
  let written = 0;
  let kept = 0;
  for (const entry of entries) {
    if (!Array.isArray(entry) || typeof entry[0] !== 'string' || typeof entry[1] !== 'string' || entry[0].length > 256 || entry[1].length > MAX_VALUE) {
      throw new LoaderError('BAD_MESSAGE', 'an entry is malformed');
    }
    if (overwrite !== true && localStorage.getItem(entry[0]) !== null) {
      kept += 1;
      continue;
    }
    localStorage.setItem(entry[0], entry[1]);
    written += 1;
  }
  return { written, kept };
}

async function handle(message) {
  switch (message.type) {
    case 'install': {
      const report = await install(message.swbn);
      say('Verified. Opening.');
      return { type: 'install.ok', id: ID, sha256: report.sha256 };
    }
    case 'storage.export':
      return { type: 'storage.exported', ...exportStorage() };
    case 'storage.import':
      return { type: 'storage.imported', ...importStorage(message.entries, message.overwrite) };
    case 'storage.clear': {
      const count = localStorage.length;
      localStorage.clear();
      return { type: 'storage.cleared', removed: count };
    }
    default:
      throw new LoaderError('BAD_MESSAGE', 'unknown request');
  }
}

if (!isKeyId(ID)) {
  say('This host name is not a key origin.');
} else if (!framed) {
  say('This is a key origin. Open it in KeyWeb Runner.');
} else {
  // Only the runner, and only as this frame's parent, may give orders.
  window.addEventListener('message', (event) => {
    if (event.origin !== RUNNER || event.source !== window.parent) return;
    const message = event.data;
    if (message === null || typeof message !== 'object' || message.keyweb !== 1 || typeof message.type !== 'string') return;
    handle(message).then(
      (reply) => post({ ...reply, rid: message.rid }),
      (error) => {
        const code = error instanceof VerifyError || error instanceof LoaderError ? error.code : 'LOADER_FAILED';
        say(`Blocked: ${code}.`);
        post({ type: 'failed', rid: message.rid, code, detail: String(error.detail || error.message || error).slice(0, 300) });
      },
    );
  });
  const storage = storageWorks();
  if (!storage) say('This browser blocks storage for embedded origins, so a key origin cannot be set up here.');
  post({ type: 'loader.ready', id: ID, storage });
}
