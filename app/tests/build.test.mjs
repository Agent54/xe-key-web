// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The build: six bundles under six keys, a catalog that matches them, one
// valid rotation certificate and three forgeries, and no key left behind.

import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { sha256Hex } from '../runner/src/engine/bytes.js';
import { chunkManifest } from '../runner/src/engine/chunks.js';
import { parseAddress, verifyNameRecord } from '../runner/src/engine/names.js';
import { BUNDLE_CSP } from '../runner/src/engine/policy.js';
import { keyDigest, verifyRotation } from '../runner/src/engine/rotation.js';
import { keyFromId, readDescriptor, verifySwbn } from '../runner/src/engine/swbn.js';
import { BUNDLE_HEADERS, buildAll, buildDemos, keyFilesInRepo, keyRing, secretsInOutput } from '../scripts/build-swbn.mjs';
import { CHUNK_SIZE, DEMO_BUILDS, REPO_ROOT, RUNNER_ID } from '../scripts/lib/site.mjs';
import { verifySignedWebBundle } from '../scripts/lib/swbn.mjs';
import { tempDir } from './helpers.mjs';

const read = (file) => new Uint8Array(readFileSync(file));

describe('a full build', () => {
  let temp;
  let out;
  let info;
  let catalog;
  const lines = [];

  before(async () => {
    temp = tempDir();
    out = join(temp.dir, 'dist');
    // Never let a developer's own packager setting change what this test checks.
    const saved = process.env.IWA_PACKAGER_CLI;
    delete process.env.IWA_PACKAGER_CLI;
    try {
      info = await buildAll({ outDir: out, log: (line) => lines.push(line) });
    } finally {
      if (saved !== undefined) process.env.IWA_PACKAGER_CLI = saved;
    }
    catalog = JSON.parse(readFileSync(join(out, 'demo-bundles', 'catalog.json'), 'utf8'));
  });
  after(() => temp.remove());

  test('writes the runner bundle, five demo bundles, four certificates and a catalog', () => {
    assert.deepEqual(readdirSync(out).sort(), ['build-info.json', 'demo-bundles', `${RUNNER_ID}-0.1.0.swbn`, `${RUNNER_ID}-0.1.0.wbn`]);
    assert.deepEqual(readdirSync(join(out, 'demo-bundles')).sort(), ['catalog.json', 'evilpad-1.0.0.swbn', 'leakytracker-1.0.0.swbn', 'localpad-1.0.0.swbn', 'localpad-1.1.0.swbn', 'names', 'peersync-calc-1.0.0.swbn', 'rotation']);
    assert.deepEqual(readdirSync(join(out, 'demo-bundles', 'names')).sort(), ['hijacked', 'normal', 'rotated']);
    assert.deepEqual(readdirSync(join(out, 'demo-bundles', 'rotation')).sort(), ['forged.json', 'stolen-key.json', 'unsigned.json', 'valid.json']);
    assert.equal(catalog.apps.length, DEMO_BUILDS.length);
    assert.deepEqual(JSON.parse(readFileSync(join(out, 'build-info.json'), 'utf8')), info);
  });

  test('signs every bundle with its own Ed25519 key, and every one verifies two ways', async () => {
    const ids = new Set([info.webBundleId]);
    for (const app of catalog.apps) {
      const bytes = read(join(out, 'demo-bundles', app.file));
      const report = await verifySwbn(bytes, { expectedId: app.id });
      assert.equal(verifySignedWebBundle(bytes, { expectedId: app.id }).webBundleId, app.id);
      assert.equal(report.sha256, app.sha256);
      assert.equal(bytes.length, app.size);
      assert.equal(app.origin, `key-web://${app.id}/`);
      assert.deepEqual([...keyFromId(app.id)], [...Buffer.from(app.publicKey, 'base64url')]);
      ids.add(app.id);
    }
    assert.equal(ids.size, 6);
    assert.equal(info.verified.distinctKeys, 6);
    assert.equal(info.verified.bundles, 6);
    assert.equal(info.verified.otherPackager, 'not run');
    const runner = read(join(out, info.swbn.file));
    assert.equal((await verifySwbn(runner, { expectedId: info.webBundleId })).id, info.webBundleId);
    assert.equal(await sha256Hex(runner), info.swbn.sha256);
  });

  test('the catalog describes exactly what was signed', async () => {
    const [pad, leaky, calc, successor, impostor] = catalog.apps;
    assert.deepEqual(catalog.apps.map((app) => `${app.slug}:${app.role}:${app.version}`), ['localpad:app:1.0.0', 'leakytracker:app:1.0.0', 'peersync-calc:app:1.0.0', 'localpad:successor:1.1.0', 'evilpad:impostor:1.0.0']);
    assert.deepEqual([pad.name, leaky.name, calc.name, successor.name, impostor.name], ['LocalPad', 'LeakyTracker', 'PeerSync Calc', 'LocalPad', 'LocalPad']);
    assert.deepEqual(pad.capabilities, []);
    assert.deepEqual(leaky.capabilities, []);
    assert.deepEqual(calc.capabilities, ['net:sync-relay', 'storage:export']);
    for (const app of catalog.apps) {
      const bytes = read(join(out, 'demo-bundles', app.file));
      assert.deepEqual(app.manifest, await chunkManifest(bytes, CHUNK_SIZE));
      assert.ok(app.manifest.chunks.length >= 6, `${app.file} should span several swarm chunks`);
      const descriptor = readDescriptor(await verifySwbn(bytes));
      assert.equal(descriptor.name, app.name);
      assert.equal(descriptor.version, app.version);
      assert.equal(descriptor.nextKeyDigest, app.nextKeyDigest);
    }
    assert.equal(catalog.chunkSize, CHUNK_SIZE);
  });

  test("LocalPad's signed bundle commits to the digest of its successor's key, and to nothing else", async () => {
    const pad = catalog.apps[0];
    const successor = catalog.apps[3];
    assert.equal(pad.nextKeyDigest, await keyDigest(keyFromId(successor.id)));
    assert.match(successor.nextKeyDigest, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(successor.nextKeyDigest, pad.nextKeyDigest);
    assert.equal(catalog.apps[1].nextKeyDigest, null);
    assert.deepEqual(catalog.rotation.from, pad.id);
    assert.deepEqual(catalog.rotation.to, successor.id);
    // The commitment is a digest. The next key itself is nowhere in the old bundle.
    const text = Buffer.from(read(join(out, 'demo-bundles', pad.file))).toString('latin1');
    assert.ok(!text.includes(successor.publicKey));
    assert.ok(!text.includes(successor.id));
  });

  test('ships one certificate that verifies and three that fail for three different reasons', async () => {
    const pad = catalog.apps[0];
    const trust = { currentId: pad.id, committedDigest: pad.nextKeyDigest, currentSequence: 0 };
    const verdict = async (name) => (await verifyRotation(JSON.parse(readFileSync(join(out, 'demo-bundles', catalog.rotation.certificates[name]), 'utf8')), trust));
    const valid = await verdict('valid');
    assert.equal(valid.ok, true);
    assert.equal(valid.to, catalog.rotation.to);
    assert.equal(valid.nextKeyDigest, catalog.apps[3].nextKeyDigest);
    assert.equal((await verdict('unsigned')).code, 'ROTATION_UNSIGNED');
    assert.equal((await verdict('forged')).code, 'ROTATION_SIGNATURE_INVALID');
    assert.equal((await verdict('stolen-key')).code, 'PRECOMMIT_MISMATCH');
    // The attacker in the forgeries is the impostor's key.
    assert.equal(JSON.parse(JSON.parse(readFileSync(join(out, 'demo-bundles', 'rotation', 'forged.json'), 'utf8')).payload).to, catalog.apps[4].id);
  });

  test('publishes every readable name on its rails, signed by its publisher, pointing at the right key', async () => {
    const record = (mode, name) => JSON.parse(readFileSync(join(out, 'demo-bundles', 'names', mode, name.rail, name.publisher, `${name.app}.json`), 'utf8'));
    assert.deepEqual(catalog.names.map((name) => name.name), [
      'localpad.lukeinth.at', 'localpad.lukeinth.dht', 'peersync.lukeinth.at', 'peersync.lukeinth.dht', 'leaky.mallory.dht',
    ]);
    const keyOf = (slug) => catalog.apps.find((app) => app.slug === slug && app.role === 'app').id;
    const publishers = new Map();
    for (const name of catalog.names) {
      assert.equal(name.key, keyOf(name.slug), name.name);
      assert.deepEqual(parseAddress(`key-web://${name.name}/`), { kind: 'name', rail: name.rail, app: name.app, publisher: name.publisher, host: name.name, address: `key-web://${name.name}/` });
      const checked = await verifyNameRecord(record('normal', name), name);
      assert.equal(checked.ok, true, name.name);
      assert.equal(checked.key, name.key);
      assert.deepEqual(checked.certificates, []);
      assert.equal(Buffer.from(checked.publisherKey).toString('base64url'), catalog.publishers[name.publisher]);
      publishers.set(name.publisher, catalog.publishers[name.publisher]);
    }
    // Two publishers, two keys. The two rails of one publisher agree on every app.
    assert.equal(new Set(publishers.values()).size, 2);
    assert.equal(catalog.names[0].key, catalog.names[1].key);
    assert.equal(catalog.names[2].key, catalog.names[3].key);
  });

  test('the hijacked records are validly signed, by the wrong publisher, for the wrong key, with a certificate that does not hold', async () => {
    const path = (mode, app) => join(out, 'demo-bundles', 'names', mode, 'at', 'lukeinth', `${app}.json`);
    const pad = catalog.apps[0];
    const impostor = catalog.apps[4];
    for (const app of ['localpad', 'peersync']) {
      const hijacked = JSON.parse(readFileSync(path('hijacked', app), 'utf8'));
      const checked = await verifyNameRecord(hijacked, { app, publisher: 'lukeinth', rail: 'at' });
      // The signature is fine. That is the point: a hijacker signs too.
      assert.equal(checked.ok, true);
      assert.equal(checked.key, impostor.id);
      assert.equal(Buffer.from(checked.publisherKey).toString('base64url'), catalog.publishers.mallory);
      assert.notEqual(Buffer.from(checked.publisherKey).toString('base64url'), catalog.publishers.lukeinth);
      const forged = await verifyRotation(checked.certificates[0], { currentId: pad.id, committedDigest: pad.nextKeyDigest, currentSequence: 0 });
      assert.equal(forged.code, 'PRECOMMIT_MISMATCH');
    }
    assert.deepEqual(catalog.hijack, { publisher: 'lukeinth', rail: 'at', by: 'mallory', key: impostor.id });
    // Only the hijacked rail and publisher have hijacked records.
    assert.deepEqual(readdirSync(join(out, 'demo-bundles', 'names', 'hijacked')), ['at']);
    assert.deepEqual(readdirSync(join(out, 'demo-bundles', 'names', 'hijacked', 'at')), ['lukeinth']);
  });

  test('the rotated record names the successor and carries the certificate that proves it', async () => {
    const pad = catalog.apps[0];
    const successor = catalog.apps[3];
    const rotated = JSON.parse(readFileSync(join(out, 'demo-bundles', 'names', 'rotated', 'at', 'lukeinth', 'localpad.json'), 'utf8'));
    const checked = await verifyNameRecord(rotated, { app: 'localpad', publisher: 'lukeinth', rail: 'at' });
    assert.equal(checked.ok, true);
    assert.equal(checked.key, successor.id);
    assert.equal(checked.sequence, 2);
    assert.equal(Buffer.from(checked.publisherKey).toString('base64url'), catalog.publishers.lukeinth);
    const proof = await verifyRotation(checked.certificates[0], { currentId: pad.id, committedDigest: pad.nextKeyDigest, currentSequence: 0 });
    assert.equal(proof.ok, true);
    assert.equal(proof.to, successor.id);
  });

  test('the impostor is the same app under a different key', async () => {
    const pad = await verifySwbn(read(join(out, 'demo-bundles', catalog.apps[0].file)));
    const fake = await verifySwbn(read(join(out, 'demo-bundles', catalog.apps[4].file)));
    assert.notEqual(pad.id, fake.id);
    assert.deepEqual([...pad.exchanges.get('/app.js').payload], [...fake.exchanges.get('/app.js').payload]);
    assert.equal(readDescriptor(fake).name, 'LocalPad');
  });

  test('the runner bundle carries the loader, the engine, the demo bundles and a strict policy on every resource', async () => {
    const report = await verifySwbn(read(join(out, info.swbn.file)));
    for (const path of ['/', '/index.html', '/app.css', '/src/main.js', '/src/engine/swbn.js', '/loader/loader.html', '/loader/sw.js', '/icon-256.png', '/.well-known/manifest.webmanifest', '/demo-bundles/catalog.json', '/demo-bundles/localpad-1.0.0.swbn', '/demo-bundles/rotation/valid.json']) {
      assert.ok(report.exchanges.has(path), path);
    }
    for (const [path, exchange] of report.exchanges) {
      assert.equal(exchange.headers['content-security-policy'], BUNDLE_CSP, path);
      assert.equal(exchange.headers['cross-origin-opener-policy'], 'same-origin', path);
      assert.equal(exchange.headers['x-content-type-options'], 'nosniff', path);
    }
    assert.equal(BUNDLE_HEADERS['content-security-policy'], BUNDLE_CSP);
    // A bundle inside the bundle is still a bundle.
    const inner = report.exchanges.get('/demo-bundles/localpad-1.0.0.swbn').payload;
    assert.equal((await verifySwbn(inner.slice(), { expectedId: catalog.apps[0].id })).ok, true);
    assert.equal(info.files, report.exchanges.size - 1);
  });

  test('leaves no key anywhere: not in the output, not in the repository', () => {
    assert.deepEqual(secretsInOutput(out), []);
    assert.deepEqual(keyFilesInRepo(), []);
    assert.equal(info.signingKey, 'ephemeral (in memory only, discarded)');
    assert.ok(lines.some((line) => /6 distinct Ed25519 keys, in memory only, now discarded/.test(line)));
    const planted = join(out, 'oops.pem');
    writeFileSync(planted, 'x');
    assert.deepEqual(secretsInOutput(out), ['oops.pem']);
    writeFileSync(planted.replace('.pem', '.txt'), ['-----BEGIN', 'PRIVATE KEY-----'].join(' '));
    assert.equal(secretsInOutput(out).length, 2);
  });

  test('every build gets fresh keys unless told to keep them', async () => {
    const again = tempDir();
    try {
      const second = await buildDemos({ outDir: join(again.dir, 'demo-bundles') });
      assert.notEqual(second.catalog.apps[0].id, catalog.apps[0].id);
    } finally {
      again.remove();
    }
  });
});

describe('keeping keys', () => {
  test('a keys folder gives the same origins on every build, in files only the owner can read', async () => {
    const temp = tempDir();
    try {
      const keysDir = join(temp.dir, 'keys');
      const first = await buildDemos({ outDir: join(temp.dir, 'a'), keys: keyRing(keysDir), issued: '2026-01-01T00:00:00.000Z' });
      const second = await buildDemos({ outDir: join(temp.dir, 'b'), keys: keyRing(keysDir), issued: '2026-01-01T00:00:00.000Z' });
      assert.deepEqual(first.catalog, second.catalog);
      for (const app of first.catalog.apps) assert.deepEqual([...read(join(temp.dir, 'a', app.file))], [...read(join(temp.dir, 'b', app.file))]);
      assert.deepEqual(readFileSync(join(temp.dir, 'a', 'rotation', 'valid.json'), 'utf8'), readFileSync(join(temp.dir, 'b', 'rotation', 'valid.json'), 'utf8'));
      const files = readdirSync(keysDir).sort();
      assert.deepEqual(files, ['impostor.pem', 'leakytracker.pem', 'localpad-v1.pem', 'localpad-v2.pem', 'localpad-v3.pem', 'peersync-calc.pem', 'publisher-lukeinth.pem', 'publisher-mallory.pem']);
      for (const name of first.catalog.names) {
        const path = join('names', 'normal', name.rail, name.publisher, `${name.app}.json`);
        assert.equal(readFileSync(join(temp.dir, 'a', path), 'utf8'), readFileSync(join(temp.dir, 'b', path), 'utf8'), path);
      }
      if (process.platform !== 'win32') for (const file of files) assert.equal(statSync(join(keysDir, file)).mode & 0o077, 0, file);
    } finally {
      temp.remove();
    }
  });

  test('a keys folder inside the repository is refused, and so are loose permissions and bad names', () => {
    const refused = join(REPO_ROOT, 'dist', 'keys-test-refused');
    assert.throws(() => keyRing(refused), /outside this repository/);
    assert.throws(() => keyRing(REPO_ROOT), /outside this repository/);
    // Refused before anything was created.
    assert.equal(existsSync(refused), false);
    const temp = tempDir();
    try {
      const ring = keyRing(temp.dir);
      assert.throws(() => ring.get('../escape'), /bad key name/);
      assert.throws(() => ring.get('UPPER'), /bad key name/);
      const key = ring.get('good');
      assert.equal(ring.get('good'), key);
      if (process.platform !== 'win32') {
        writeFileSync(join(temp.dir, 'loose.pem'), readFileSync(join(temp.dir, 'good.pem')), { mode: 0o644 });
        assert.throws(() => keyRing(temp.dir).get('loose'), /chmod 600/);
      }
      writeFileSync(join(temp.dir, 'junk.pem'), 'not a key', { mode: 0o600 });
      assert.throws(() => keyRing(temp.dir).get('junk'), /unencrypted PKCS#8 PEM/);
    } finally {
      temp.remove();
    }
  });
});

describe('what the build refuses', () => {
  test('to empty a folder it did not make', async () => {
    const temp = tempDir();
    try {
      const precious = join(temp.dir, 'documents');
      mkdirSync(precious);
      writeFileSync(join(precious, 'thesis.txt'), 'years of work');
      await assert.rejects(buildDemos({ outDir: precious }), /refusing to empty/);
      assert.equal(readFileSync(join(precious, 'thesis.txt'), 'utf8'), 'years of work');
      await assert.rejects(buildDemos({}), /needs an output folder/);
    } finally {
      temp.remove();
    }
  });

  test('to carry a bundle from an earlier build along', async () => {
    const temp = tempDir();
    try {
      const dir = join(temp.dir, 'demo-bundles');
      await buildDemos({ outDir: dir });
      writeFileSync(join(dir, 'stale-9.9.9.swbn'), 'left over');
      await buildDemos({ outDir: dir });
      assert.equal(existsSync(join(dir, 'stale-9.9.9.swbn')), false);
      assert.equal(readdirSync(dir).filter((name) => name.endsWith('.swbn')).length, 5);
    } finally {
      temp.remove();
    }
  });
});
