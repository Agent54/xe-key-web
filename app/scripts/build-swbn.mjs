#!/usr/bin/env node
// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Builds every signed bundle this project has:
//
//   dist/demo-bundles/*.swbn          the demo apps, each signed by its own Ed25519 key:
//                                     LocalPad, LeakyTracker, PeerSync Calc, LocalPad again
//                                     under its rotated key, and an impostor "LocalPad"
//   dist/demo-bundles/rotation/*.json one valid key-rotation certificate and three forgeries
//   dist/demo-bundles/names/          signed name records for the resolver rails: the honest
//                                     ones, a hijacked set, and one published after rotation
//   dist/demo-bundles/catalog.json    what the runner and the mirror read: IDs, hashes, chunk lists
//   dist/keyweb-runner-<v>.swbn       KeyWeb Runner itself, as an Isolated Web App, with the
//                                     demo bundles inside it
//
//   node scripts/build-swbn.mjs                    build into dist/
//   node scripts/build-swbn.mjs --out <dir>        write somewhere else
//   node scripts/build-swbn.mjs --keys-dir <dir>   keep the signing keys in a folder OUTSIDE this
//                                                  repository, so IDs survive a rebuild
//
// Signing keys. With no --keys-dir, every key is a fresh Ed25519 key that
// exists only in this process's memory: it is never written to disk, so it
// cannot be committed, and each build gets new origins. With --keys-dir the
// keys are unencrypted PKCS#8 PEM files, mode 600, in a folder that must be
// outside the repository; a key inside the repository is refused, and the
// build fails if any key-like file is found in the tree before or after.
//
// The build refuses to sign anything the zero-sink gate would reject. Every
// bundle is re-read from disk and verified twice, by node:crypto and by the
// page's own WebCrypto engine, before success is reported. If
// IWA_PACKAGER_CLI names another packager's command-line entry, each one is
// verified with that tool as well.

import { spawnSync } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64url } from '../runner/src/engine/bytes.js';
import { chunkManifest } from '../runner/src/engine/chunks.js';
import { verifyNameRecord } from '../runner/src/engine/names.js';
import { BUNDLE_CSP } from '../runner/src/engine/policy.js';
import { keyDigest } from '../runner/src/engine/rotation.js';
import { keyWebOrigin, readDescriptor, verifySwbn } from '../runner/src/engine/swbn.js';
import { KEY_FILE, listRepo } from './hygiene-check.mjs';
import { CHUNK_SIZE, DEMO_BUILDS, DEMO_NAMES, DIST_DIR, HIJACK, REPO_ROOT, RUNNER_ID, demoFiles, listTree, runnerFiles } from './lib/site.mjs';
import { buildWebBundle, filesToExchanges, makeNameRecord, makeRotation, rawPublicKey, sha256Hex, signWebBundle, verifySignedWebBundle, webBundleId } from './lib/swbn.mjs';
import { scanFile } from './zero-sink-check.mjs';

const SECRET_CONTENT = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/;
const SCANNED_TEXT = /\.(html?|m?js|css|svg)$/i;

/** Response headers stored on every resource in the runner's own bundle. */
export const BUNDLE_HEADERS = Object.freeze({
  'content-security-policy': BUNDLE_CSP,
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
  'x-content-type-options': 'nosniff',
});

/**
 * Headers stored in a demo app's bundle. They are the developer's; the
 * sandbox ignores them and applies its own policy to every response.
 */
export const DEMO_HEADERS = Object.freeze({ 'x-content-type-options': 'nosniff' });

/** Key-like files anywhere in the repository. There must be none. */
export function keyFilesInRepo(root = REPO_ROOT) {
  return listRepo(root).map((file) => file.path).filter((path) => KEY_FILE.test(path));
}

function inside(dir, target) {
  const rel = relative(dir, target);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Hands out one Ed25519 private key per name. In memory by default; in
 * `dir` (outside the repository, mode 600) when one is given. A private
 * key never leaves this object except to sign.
 */
export function keyRing(dir = null) {
  const keys = new Map();
  let folder = null;
  if (dir !== null) {
    // Decide before creating anything: resolve symlinks in whatever part of
    // the path already exists, and refuse a place inside the repository.
    const wanted = resolve(dir);
    let existing = wanted;
    while (!existsSync(existing) && dirname(existing) !== existing) existing = dirname(existing);
    const canonical = join(realpathSync(existing), relative(existing, wanted));
    const repo = realpathSync(REPO_ROOT);
    if (inside(repo, canonical) || inside(resolve(REPO_ROOT), wanted)) throw new Error('--keys-dir must point outside this repository');
    mkdirSync(wanted, { recursive: true, mode: 0o700 });
    folder = realpathSync(wanted);
    if (inside(repo, folder)) throw new Error('--keys-dir must point outside this repository');
  }
  const load = (name) => {
    if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(name)) throw new Error(`bad key name: ${name}`);
    if (folder === null) return generateKeyPairSync('ed25519').privateKey;
    const file = join(folder, `${name}.pem`);
    if (!existsSync(file)) {
      const fresh = generateKeyPairSync('ed25519').privateKey;
      writeFileSync(file, fresh.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
      chmodSync(file, 0o600);
      return fresh;
    }
    if (process.platform !== 'win32' && (statSync(file).mode & 0o077) !== 0) throw new Error(`the key file ${name}.pem must not be readable by group or others (chmod 600)`);
    let key;
    try {
      key = createPrivateKey({ key: readFileSync(file), format: 'pem' });
    } catch {
      throw new Error(`could not read ${name}.pem: it must be an unencrypted PKCS#8 PEM`);
    }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${name}.pem is not an Ed25519 key`);
    return key;
  };
  return {
    persistent: folder !== null,
    get(name) {
      if (!keys.has(name)) keys.set(name, load(name));
      return keys.get(name);
    },
  };
}

/** Reads files for a bundle, refusing anything that must not be signed. */
function collect(fileMap, repoPrefix) {
  const files = [];
  for (const [path, abs] of fileMap) {
    if (KEY_FILE.test(path)) throw new Error(`refusing to package a key-like file: ${path}`);
    const bytes = new Uint8Array(readFileSync(abs));
    if (SECRET_CONTENT.test(Buffer.from(bytes).toString('latin1'))) throw new Error(`refusing to package a file that holds a private key: ${path}`);
    if (SCANNED_TEXT.test(path)) {
      const repoPath = relative(REPO_ROOT, abs).split(sep).join('/');
      const { findings } = scanFile(repoPath.startsWith('..') ? `${repoPrefix}/${path}` : repoPath, Buffer.from(bytes).toString('utf8'));
      if (findings.length) throw new Error(`refusing to sign ${path}:${findings[0].line}: ${findings[0].what} (${findings[0].rule})`);
    }
    files.push({ path, bytes });
  }
  return files;
}

const jsonBytes = (value) => new Uint8Array(Buffer.from(`${JSON.stringify(value, null, 2)}\n`));
const parseJson = (file) => JSON.parse(Buffer.from(file.bytes).toString('utf8'));

function needFile(files, path, what) {
  const file = files.find((entry) => entry.path === path);
  if (!file) throw new Error(`${what} has no ${path}`);
  return file;
}

/** Builds and signs one demo app. Resolves with the catalog entry plus the bytes. */
async function buildDemo(build, keys) {
  const files = collect(demoFiles(build.source), `demos/${build.source}`);
  needFile(files, 'index.html', build.source);
  const manifestFile = needFile(files, '.well-known/manifest.webmanifest', build.source);
  const descriptorFile = needFile(files, '.well-known/key-web.json', build.source);
  const manifest = parseJson(manifestFile);
  const descriptor = parseJson(descriptorFile);
  const version = build.version || manifest.version;
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`${build.source}: the manifest version must be MAJOR.MINOR.PATCH`);

  // The descriptor is signed with everything else. It carries the commitment
  // to the next key: only that key's digest, never the key.
  const key = keys.get(build.key);
  const nextKeyDigest = build.nextKey ? await keyDigest(rawPublicKey(keys.get(build.nextKey))) : null;
  manifestFile.bytes = jsonBytes({ ...manifest, version });
  descriptorFile.bytes = jsonBytes({ ...descriptor, version, ...(nextKeyDigest ? { next_key_digest: nextKeyDigest } : {}) });

  const publicKey = rawPublicKey(key);
  const id = webBundleId(publicKey);
  const signed = signWebBundle(buildWebBundle(filesToExchanges(files, id, DEMO_HEADERS)), key);
  verifySignedWebBundle(signed.swbn, { expectedId: id });
  const report = await verifySwbn(signed.swbn, { expectedId: id });
  const described = readDescriptor(report);
  return {
    entry: {
      slug: build.slug,
      role: build.role,
      name: described.name,
      summary: typeof manifest.description === 'string' ? manifest.description : '',
      version,
      id,
      origin: keyWebOrigin(id),
      publicKey: base64url(publicKey),
      file: `${build.slug}-${version}.swbn`,
      size: signed.swbn.length,
      sha256: sha256Hex(signed.swbn),
      capabilities: described.capabilities,
      nextKeyDigest: described.nextKeyDigest,
      manifest: await chunkManifest(signed.swbn, CHUNK_SIZE),
    },
    swbn: signed.swbn,
    files: files.length,
  };
}

/**
 * Builds the demo bundles, the rotation certificates and the catalog into
 * `outDir`. Resolves with {catalog, bundles: [{entry, swbn}]}.
 */
export async function buildDemos({ outDir, keys = keyRing(), issued = null } = {}) {
  if (!outDir) throw new Error('buildDemos needs an output folder');
  // Start clean, so a bundle from an earlier build cannot ride along. Only a
  // folder this build made before (it has a catalog) is ever emptied.
  if (existsSync(outDir) && readdirSync(outDir).length > 0) {
    if (!existsSync(join(outDir, 'catalog.json'))) throw new Error(`refusing to empty ${outDir}: it is not a demo-bundles folder`);
    rmSync(outDir, { recursive: true, force: true });
  }
  const bundles = [];
  for (const build of DEMO_BUILDS) bundles.push(await buildDemo(build, keys));
  const ids = new Set(bundles.map((bundle) => bundle.entry.id));
  if (ids.size !== bundles.length) throw new Error('two demo bundles were signed by the same key');

  const original = bundles.find((bundle) => bundle.entry.slug === 'localpad' && bundle.entry.role === 'app').entry;
  const successor = bundles.find((bundle) => bundle.entry.role === 'successor').entry;
  const when = issued || (process.env.SOURCE_DATE_EPOCH ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString() : new Date().toISOString());
  const outgoing = keys.get('localpad-v1');
  const incoming = keys.get('localpad-v2');
  const attacker = keys.get('impostor');
  const honest = { fromId: original.id, toPublicKey: rawPublicKey(incoming), sequence: 1, nextKeyDigest: successor.nextKeyDigest, issued: when };
  const hostile = { fromId: original.id, toPublicKey: rawPublicKey(attacker), sequence: 1, nextKeyDigest: null, issued: when };
  const certificates = {
    // The real thing: signed by the outgoing key, for the key it committed to, which signs too.
    valid: makeRotation({ ...honest, signFrom: outgoing, signTo: incoming }),
    // The same claim with nobody's signature on it.
    unsigned: makeRotation({ ...honest, signFrom: null, signTo: null }),
    // A stranger claims the origin and signs with their own key.
    forged: makeRotation({ ...hostile, signFrom: attacker, signTo: attacker }),
    // The worst case: the outgoing key itself was stolen and really did sign,
    // but for a key that was never committed to.
    'stolen-key': makeRotation({ ...hostile, signFrom: outgoing, signTo: attacker }),
  };

  // Name records: what each resolver rail answers for each human-readable
  // name, signed by the publisher's own key. Three sets, so the demo can
  // switch what a rail says:
  //   normal    the truth
  //   hijacked  the publisher's handle taken over on one rail: the same
  //             names, now pointing at the impostor's key, signed by the
  //             hijacker, with a rotation certificate that does not hold
  //   rotated   the truth after LocalPad's key rotation: the new key, with
  //             the certificate that proves the old key handed over
  const records = [];
  const names = [];
  const publisherKey = (publisher) => keys.get(`publisher-${publisher}`);
  const appOf = (slug) => bundles.find((bundle) => bundle.entry.slug === slug && bundle.entry.role === 'app').entry;
  const impostor = bundles.find((bundle) => bundle.entry.role === 'impostor').entry;
  const record = (mode, { app, publisher, rail }, fields) => {
    const made = makeNameRecord({ app, publisher, rail, issued: when, ...fields });
    records.push({ path: join('names', mode, rail, publisher, `${app}.json`), record: made });
    return made;
  };
  for (const entry of DEMO_NAMES) {
    const target = appOf(entry.slug);
    for (const rail of entry.rails) {
      const name = { app: entry.app, publisher: entry.publisher, rail };
      record('normal', name, { key: target.id, sequence: 1, signKey: publisherKey(entry.publisher) });
      names.push({ name: `${entry.app}.${entry.publisher}.${rail}`, ...name, slug: entry.slug, key: target.id });
      if (entry.publisher === HIJACK.publisher && rail === HIJACK.rail) {
        record('hijacked', name, { key: impostor.id, sequence: 2, signKey: publisherKey(HIJACK.by), rotation: [certificates['stolen-key']] });
        if (target.id === original.id) record('rotated', name, { key: successor.id, sequence: 2, signKey: publisherKey(entry.publisher), rotation: [certificates.valid] });
      }
    }
  }
  for (const { record: made } of records) {
    const payload = JSON.parse(made.payload);
    const checked = await verifyNameRecord(made, payload);
    if (!checked.ok) throw new Error(`a name record does not verify: ${checked.code}`);
  }

  const catalog = {
    format: 'key-web-catalog/1',
    chunkSize: CHUNK_SIZE,
    apps: bundles.map((bundle) => bundle.entry),
    names,
    publishers: Object.fromEntries([...new Set(DEMO_NAMES.map((entry) => entry.publisher))].map((publisher) => [publisher, base64url(rawPublicKey(publisherKey(publisher)))])),
    hijack: { ...HIJACK, key: impostor.id },
    rotation: {
      from: original.id,
      to: successor.id,
      certificates: Object.fromEntries(Object.keys(certificates).map((name) => [name, `rotation/${name}.json`])),
    },
  };

  mkdirSync(join(outDir, 'rotation'), { recursive: true });
  for (const bundle of bundles) writeFileSync(join(outDir, bundle.entry.file), bundle.swbn);
  for (const [name, certificate] of Object.entries(certificates)) writeFileSync(join(outDir, 'rotation', `${name}.json`), `${JSON.stringify(certificate, null, 2)}\n`);
  for (const { path, record: made } of records) {
    mkdirSync(dirname(join(outDir, path)), { recursive: true });
    writeFileSync(join(outDir, path), `${JSON.stringify(made, null, 2)}\n`);
  }
  // Written last: the dev server reloads when this file changes.
  writeFileSync(join(outDir, 'catalog.json'), `${JSON.stringify(catalog, null, 2)}\n`);
  return { catalog, bundles };
}

/**
 * Builds, signs and verifies the runner's own bundle in memory, with the
 * demo bundles from `demoDir` inside it.
 */
export async function buildRunner({ demoDir, privateKey = null } = {}) {
  const files = collect(runnerFiles(), 'runner');
  if (demoDir) {
    for (const [path, abs] of listTree(demoDir)) {
      if (KEY_FILE.test(path)) throw new Error(`refusing to package a key-like file: ${path}`);
      files.push({ path: `demo-bundles/${path}`, bytes: new Uint8Array(readFileSync(abs)) });
    }
  }
  needFile(files, 'index.html', 'the runner');
  const version = parseJson(needFile(files, '.well-known/manifest.webmanifest', 'the runner')).version;
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error('the manifest version must be MAJOR.MINOR.PATCH');
  const ephemeral = privateKey === null;
  const key = ephemeral ? generateKeyPairSync('ed25519').privateKey : privateKey;
  const id = webBundleId(rawPublicKey(key));
  const exchanges = filesToExchanges(files, id, BUNDLE_HEADERS);
  const wbn = buildWebBundle(exchanges);
  const signed = signWebBundle(wbn, key);
  const verified = verifySignedWebBundle(signed.swbn, { expectedId: id });
  await verifySwbn(signed.swbn, { expectedId: id });
  return {
    swbn: signed.swbn,
    wbn,
    webBundleId: id,
    origin: verified.origin,
    version,
    files: files.length,
    exchanges: exchanges.length,
    urls: verified.urls,
    publicKey: base64url(signed.publicKey),
    signingKey: ephemeral ? 'ephemeral (in memory only, discarded)' : 'kept in --keys-dir, outside the repository',
  };
}

/** Verifies a bundle with another packager's CLI. Returns its answer, or null when none is configured. */
export function crossVerify(file, id, cli = process.env.IWA_PACKAGER_CLI) {
  if (!cli) return null;
  const candidates = [cli, join(cli, 'bin', 'xe-iwa-packager.mjs')];
  const entry = candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  if (!entry) throw new Error('IWA_PACKAGER_CLI is set but does not name a packager entry point');
  const run = spawnSync(process.execPath, [entry, 'verify', '--swbn', file, '--expect-id', id], { encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`the other packager rejected ${relative(process.cwd(), file)}: ${(run.stderr || run.stdout).trim().split('\n').pop()}`);
  const answer = JSON.parse(run.stdout);
  if (answer.ok !== true || answer.webBundleId !== id) throw new Error(`the other packager disagrees about ${relative(process.cwd(), file)}`);
  return answer;
}

/** Private key material anywhere under a build output folder. There must be none. */
export function secretsInOutput(dir) {
  const hits = [];
  const walk = (abs) => {
    for (const name of readdirSync(abs)) {
      const child = join(abs, name);
      if (statSync(child).isDirectory()) walk(child);
      else if (KEY_FILE.test(name) || SECRET_CONTENT.test(readFileSync(child).toString('latin1'))) hits.push(relative(dir, child));
    }
  };
  walk(dir);
  return hits;
}

/**
 * The whole build. Resolves with the build-info object that is also written
 * to <outDir>/build-info.json.
 */
export async function buildAll({ outDir = DIST_DIR, keysDir = null, log = () => {} } = {}) {
  const before = keyFilesInRepo();
  if (before.length) throw new Error(`key-like files in the repository (remove them): ${before.join(', ')}`);
  const out = resolve(outDir);
  const demoDir = join(out, 'demo-bundles');
  const keys = keyRing(keysDir);

  const demos = await buildDemos({ outDir: demoDir, keys });
  const runner = await buildRunner({ demoDir, privateKey: keys.persistent ? keys.get(RUNNER_ID) : null });
  const base = `${RUNNER_ID}-${runner.version}`;
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, `${base}.swbn`), runner.swbn);
  writeFileSync(join(out, `${base}.wbn`), runner.wbn);

  // Trust nothing held in memory: read every file back and verify that, three ways.
  const outputs = [
    ...demos.bundles.map((bundle) => ({ label: `${bundle.entry.slug} ${bundle.entry.version} (${bundle.entry.role})`, file: join(demoDir, bundle.entry.file), id: bundle.entry.id, files: bundle.files })),
    { label: `${RUNNER_ID} ${runner.version}`, file: join(out, `${base}.swbn`), id: runner.webBundleId, files: runner.files },
  ];
  let other = 0;
  for (const output of outputs) {
    const bytes = new Uint8Array(readFileSync(output.file));
    verifySignedWebBundle(bytes, { expectedId: output.id });
    await verifySwbn(bytes, { expectedId: output.id });
    if (crossVerify(output.file, output.id)) other += 1;
    output.size = bytes.length;
    output.sha256 = sha256Hex(bytes);
    log(`signed    ${relative(process.cwd(), output.file)}  ${output.files} files, ${bytes.length} bytes`);
    log(`          key-web://${output.id}/`);
  }

  const info = {
    app: RUNNER_ID,
    version: runner.version,
    webBundleId: runner.webBundleId,
    origin: runner.origin,
    swbn: { file: `${base}.swbn`, sha256: sha256Hex(runner.swbn), size: runner.swbn.length },
    wbn: { file: `${base}.wbn`, sha256: sha256Hex(runner.wbn), size: runner.wbn.length },
    files: runner.files,
    exchanges: runner.exchanges,
    publicKey: runner.publicKey,
    signingKey: runner.signingKey,
    demoBundles: demos.catalog.apps.map((app) => ({ file: `demo-bundles/${app.file}`, role: app.role, name: app.name, version: app.version, webBundleId: app.id, sha256: app.sha256, size: app.size, chunks: app.manifest.chunks.length })),
    rotationCertificates: Object.values(demos.catalog.rotation.certificates).map((path) => `demo-bundles/${path}`),
    verified: {
      integrityBlock: 'v2',
      bundles: outputs.length,
      distinctKeys: new Set(outputs.map((output) => output.id)).size,
      verifiers: ['node:crypto', 'WebCrypto engine (runner/src/engine/swbn.js)', ...(other === outputs.length ? ['other packager CLI'] : [])],
      otherPackager: other === outputs.length ? `ok (${other} of ${outputs.length} bundles)` : 'not run',
    },
  };
  writeFileSync(join(out, 'build-info.json'), `${JSON.stringify(info, null, 2)}\n`);

  const after = keyFilesInRepo();
  if (after.length) throw new Error(`key-like files appeared in the repository: ${after.join(', ')}`);
  const leaked = secretsInOutput(out);
  if (leaked.length) throw new Error(`private key material in the build output: ${leaked.join(', ')}`);

  log(`keys      ${info.verified.distinctKeys} distinct Ed25519 keys, ${keys.persistent ? 'kept in --keys-dir' : 'in memory only, now discarded'}`);
  log(`verified  ${outputs.length} bundles: integrity block v2, signature valid, ID derived from the signing key`);
  log(`          by node:crypto and by the WebCrypto engine the page runs`);
  log(`          other packager: ${other === outputs.length ? `accepted all ${other}` : 'not run (set IWA_PACKAGER_CLI to check with one)'}`);
  return info;
}

async function main(argv) {
  const option = (name) => {
    const index = argv.indexOf(name);
    return index >= 0 ? argv[index + 1] : undefined;
  };
  await buildAll({ outDir: resolve(option('--out') || DIST_DIR), keysDir: option('--keys-dir') || null, log: (line) => console.log(line) });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`build-swbn: ${error.message}`);
    process.exitCode = 1;
  });
}
