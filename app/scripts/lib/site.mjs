// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// What the dev server, the packager, the gates and the tests agree on:
// where things live, which files ship, and which demo apps are built.

import { lstatSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { APP_PORT, CHUNK_SIZE, MIRROR_PORT, PEER_COUNT } from '../../runner/src/config.js';

export { APP_PORT, CHUNK_SIZE, MIRROR_PORT, PEER_COUNT };

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const RUNNER_ID = 'keyweb-runner';
export const RUNNER_DIR = join(REPO_ROOT, 'runner');
export const LOADER_DIR = join(RUNNER_DIR, 'loader');
export const ENGINE_DIR = join(RUNNER_DIR, 'src', 'engine');
export const DEMOS_DIR = join(REPO_ROOT, 'demos');
export const DIST_DIR = join(REPO_ROOT, 'dist');
export const DEMO_BUNDLES_DIR = join(DIST_DIR, 'demo-bundles');

/** Folders and root files this project owns. The gates scan exactly these. */
export const SCAN_ROOTS = Object.freeze(['runner', 'demos', 'scripts', 'tests', '.forgejo']); // fg-gate-allow: CI workflow directory
export const ROOT_FILES = Object.freeze(['README.md', 'LICENSE', 'package.json', '.gitignore']);
export const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', '.run']);

/**
 * The signed demo apps. Each `key` names a distinct Ed25519 key made at
 * build time; `nextKey` is the key whose digest the bundle commits to for
 * a later rotation.
 *
 *   app        listed on the start page
 *   successor  the same app after its key was rotated
 *   impostor   the same files signed by a stranger's key, claiming the same name
 */
export const DEMO_BUILDS = Object.freeze([
  { slug: 'localpad', source: 'localpad', role: 'app', key: 'localpad-v1', nextKey: 'localpad-v2' },
  { slug: 'leakytracker', source: 'leakytracker', role: 'app', key: 'leakytracker' },
  { slug: 'peersync-calc', source: 'peersync-calc', role: 'app', key: 'peersync-calc' },
  { slug: 'localpad', source: 'localpad', role: 'successor', key: 'localpad-v2', nextKey: 'localpad-v3', version: '1.1.0' },
  { slug: 'evilpad', source: 'localpad', role: 'impostor', key: 'impostor' },
]);

/**
 * The human-readable names the demo apps are published under, and on which
 * resolver rails. key-web://<app>.<publisher>.<rail>/ resolves to the key
 * that signs the demo app with that slug. Each publisher has its own
 * Ed25519 key, made at build time, that signs its name records.
 */
export const DEMO_NAMES = Object.freeze([
  { app: 'localpad', publisher: 'lukeinth', rails: ['at', 'dht'], slug: 'localpad' },
  { app: 'peersync', publisher: 'lukeinth', rails: ['at', 'dht'], slug: 'peersync-calc' },
  { app: 'leaky', publisher: 'mallory', rails: ['dht'], slug: 'leakytracker' },
]);

/** Whose handle gets taken over in the hijack demo, on which rail, and by whom. */
export const HIJACK = Object.freeze({ publisher: 'lukeinth', rail: 'at', by: 'mallory' });

/**
 * Files every demo app gets a copy of: the client side of the runner's
 * message protocol, and the stylesheet the three apps share.
 */
export const SHARED_DIR = join(DEMOS_DIR, 'shared');
export const SHARED_FILES = Object.freeze(['keyweb-client.js', 'base.css']);

const MIME = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json; charset=utf-8',
  webmanifest: 'application/manifest+json; charset=utf-8',
  svg: 'image/svg+xml',
  png: 'image/png',
  txt: 'text/plain; charset=utf-8',
  swbn: 'application/octet-stream',
};

export function mimeFor(path) {
  const match = /\.([A-Za-z0-9]+)$/.exec(path);
  return (match && MIME[match[1].toLowerCase()]) || 'application/octet-stream';
}

/** Every regular file under `dir`, as sorted [relative posix path, absolute path]. Symlinks are refused. */
export function listTree(dir) {
  const out = [];
  const walk = (abs, rel) => {
    for (const name of readdirSync(abs).sort()) {
      if (name === '.DS_Store' || SKIP_DIRS.has(name)) continue;
      const child = join(abs, name);
      const childRel = rel ? `${rel}/${name}` : name;
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) throw new Error(`symlinks are not allowed here: ${childRel}`);
      if (stat.isDirectory()) walk(child, childRel);
      else if (stat.isFile()) out.push([childRel, child]);
    }
  };
  walk(dir, '');
  return out;
}

/** The files of the runner itself, as a Map of bundle path -> absolute path. */
export function runnerFiles() {
  return new Map(listTree(RUNNER_DIR));
}

/** The files of one demo app, plus its copies of the shared files. */
export function demoFiles(source) {
  const files = new Map(listTree(join(DEMOS_DIR, source)));
  for (const name of SHARED_FILES) {
    if (files.has(name)) throw new Error(`${source} must not ship its own ${name}`);
    files.set(name, join(SHARED_DIR, name));
  }
  return files;
}
