// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Shared by the tests: a temporary folder, freshly built demo bundles, a
// tiny signed bundle made to order, and a raw HTTP client that can send any
// Host header.

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildDemos } from '../scripts/build-swbn.mjs';
import { buildWebBundle, filesToExchanges, rawPublicKey, signWebBundle, webBundleId } from '../scripts/lib/swbn.mjs';

export function tempDir(prefix = 'keyweb-test-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, remove: () => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }) };
}

/** Builds the demo bundles into a temporary folder. Call remove() when done. */
export async function builtDemos() {
  const temp = tempDir();
  const dir = join(temp.dir, 'demo-bundles');
  const { catalog } = await buildDemos({ outDir: dir, issued: '2026-01-01T00:00:00.000Z' });
  const find = (slug, role = 'app') => catalog.apps.find((app) => app.slug === slug && app.role === role);
  return {
    dir,
    catalog,
    find,
    bytes: (app) => new Uint8Array(readFileSync(join(dir, app.file))),
    certificate: (name) => JSON.parse(readFileSync(join(dir, catalog.rotation.certificates[name]), 'utf8')),
    remove: temp.remove,
  };
}

export const newKey = () => generateKeyPairSync('ed25519').privateKey;

const text = (value) => new Uint8Array(Buffer.from(value));

/** A small, valid signed bundle: {swbn, id, key, wbn}. `files` maps path to text. */
export function tinyBundle({ key = newKey(), files = { 'index.html': '<!doctype html><title>tiny</title>', 'app.js': 'export const tiny = true;\n' }, headers = {} } = {}) {
  const id = webBundleId(rawPublicKey(key));
  const wbn = buildWebBundle(filesToExchanges(Object.entries(files).map(([path, body]) => ({ path, bytes: text(body) })), id, headers));
  return { ...signWebBundle(wbn, key), id, key, wbn };
}

/**
 * One HTTP request to loopback with any Host header, which fetch() will not
 * send. Resolves with {status, headers, body (Buffer), text, json()}.
 */
export function request(port, { host = 'localhost', path = '/', method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((done, fail) => {
    const outgoing = httpRequest({ host: '127.0.0.1', port, path, method, headers: { Host: `${host}:${port}`, ...headers }, agent: false }, (response) => {
      const parts = [];
      response.on('data', (part) => parts.push(part));
      response.on('end', () => {
        const bytes = Buffer.concat(parts);
        done({ status: response.statusCode, headers: response.headers, body: bytes, text: bytes.toString('utf8'), json: () => JSON.parse(bytes.toString('utf8')) });
      });
    });
    outgoing.on('error', fail);
    if (body !== null) outgoing.write(body);
    outgoing.end();
  });
}
