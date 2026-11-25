// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The packer, and agreement with another packager's verifier when
// IWA_PACKAGER_CLI names one.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { parseWebBundle } from '../runner/src/engine/swbn.js';
import { crossVerify } from '../scripts/build-swbn.mjs';
import { buildWebBundle, bundleMime, filesToExchanges, rawPublicKey, sha256Hex, signWebBundle, verifySignedWebBundle, webBundleId } from '../scripts/lib/swbn.mjs';
import { newKey, tempDir, tinyBundle } from './helpers.mjs';

const bytes = (value) => new Uint8Array(Buffer.from(value));

describe('the packer', () => {
  test('writes a b2 bundle that reads back exactly', () => {
    const exchanges = [
      { url: 'isolated-app://x/', status: 200, headers: { 'content-type': 'text/html', 'X-Extra': 'kept' }, payload: bytes('<!doctype html>') },
      { url: 'isolated-app://x/empty', status: 200, headers: { 'content-type': 'text/plain' }, payload: new Uint8Array(0) },
      { url: 'isolated-app://x/big', status: 200, headers: { 'content-type': 'application/octet-stream' }, payload: new Uint8Array(randomBytes(70000)) },
    ];
    const wbn = buildWebBundle(exchanges);
    assert.equal(new DataView(wbn.buffer, wbn.length - 8, 8).getBigUint64(0), BigInt(wbn.length));
    // The index is a canonical CBOR map, so it lists URLs by length, then bytes.
    const parsed = new Map(parseWebBundle(wbn).map((exchange) => [exchange.url, exchange]));
    assert.deepEqual([...parsed.keys()], ['isolated-app://x/', 'isolated-app://x/big', 'isolated-app://x/empty']);
    assert.equal(parsed.get('isolated-app://x/').headers['x-extra'], 'kept');
    assert.equal(parsed.get('isolated-app://x/').status, 200);
    assert.deepEqual([...parsed.get('isolated-app://x/big').payload], [...exchanges[2].payload]);
    assert.equal(parsed.get('isolated-app://x/empty').payload.length, 0);
  });

  test('refuses duplicate URLs and bad headers', () => {
    const one = { url: 'isolated-app://x/', status: 200, headers: { 'content-type': 'text/html' }, payload: bytes('a') };
    assert.throws(() => buildWebBundle([one, one]), /duplicate URL/);
    assert.throws(() => buildWebBundle([{ ...one, headers: { 'bad name': 'x' } }]), /bad header name/);
    assert.throws(() => buildWebBundle([{ ...one, headers: { 'content-type': 'text/html\r\nx-injected: 1' } }]), /bad header value/);
  });

  test('refuses paths that would escape or collide', () => {
    for (const path of ['../up.js', 'a//b.js', './x', 'a/../b']) {
      assert.throws(() => filesToExchanges([{ path, bytes: bytes('x') }], 'x'.repeat(56), {}), /bad path/);
    }
    const [space] = filesToExchanges([{ path: "it's a file (1).js", bytes: bytes('x') }], 'x'.repeat(56), {});
    assert.ok(space.url.endsWith('/it%27s%20a%20file%20%281%29.js'));
  });

  test('picks content types by extension', () => {
    assert.equal(bundleMime('index.html'), 'text/html');
    assert.equal(bundleMime('a/b/app.MJS'), 'text/javascript');
    assert.equal(bundleMime('.well-known/manifest.webmanifest'), 'application/manifest+json');
    assert.equal(bundleMime('mystery'), 'application/octet-stream');
  });

  test('signing derives the ID from the key and refuses a public key or junk', () => {
    const key = newKey();
    const bundle = tinyBundle({ key });
    assert.equal(bundle.webBundleId, webBundleId(rawPublicKey(key)));
    assert.equal(verifySignedWebBundle(bundle.swbn, { expectedId: bundle.id }).webBundleId, bundle.id);
    assert.throws(() => verifySignedWebBundle(bundle.swbn, { expectedId: webBundleId(rawPublicKey(newKey())) }), /different Web Bundle ID/);
    assert.throws(() => signWebBundle(bytes('junk'), key));
    assert.throws(() => signWebBundle(bundle.wbn, { type: 'public' }), /private key/);
  });
});

describe('agreement with another packager', () => {
  const cli = process.env.IWA_PACKAGER_CLI;
  const entry = cli && [cli, join(cli, 'bin', 'xe-iwa-packager.mjs')].find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  const skip = entry ? false : 'set IWA_PACKAGER_CLI to another packager to run this';

  test('with none configured, cross-verification is skipped rather than faked', () => {
    assert.equal(crossVerify('/nonexistent.swbn', 'x', ''), null);
    assert.throws(() => crossVerify('/nonexistent.swbn', 'x', '/no/such/packager'), /does not name a packager/);
  });

  test('it accepts our bundles and derives the same ID', { skip }, () => {
    const temp = tempDir();
    try {
      const bundle = tinyBundle();
      const file = join(temp.dir, 'tiny.swbn');
      writeFileSync(file, bundle.swbn);
      const answer = crossVerify(file, bundle.id, cli);
      assert.equal(answer.ok, true);
      assert.equal(answer.webBundleId, bundle.id);
      assert.equal(answer.sha256, sha256Hex(bundle.swbn));
      const inspected = JSON.parse(spawnSync(process.execPath, [entry, 'inspect', '--swbn', file], { encoding: 'utf8' }).stdout);
      assert.equal(inspected.signatures.length, 1);
      assert.equal(inspected.signatures[0].valid, true);
      assert.equal(inspected.signatures[0].idDerivedFromThisKey, true);
      assert.equal(inspected.urls.length, 3);
    } finally {
      temp.remove();
    }
  });

  test('it rejects the same bundle with one byte changed, and with the wrong expected ID', { skip }, () => {
    const temp = tempDir();
    try {
      const bundle = tinyBundle();
      const tampered = bundle.swbn.slice();
      tampered[tampered.length - 30] ^= 1;
      const file = join(temp.dir, 'tampered.swbn');
      writeFileSync(file, tampered);
      assert.throws(() => crossVerify(file, bundle.id, cli), /rejected/);
      const good = join(temp.dir, 'good.swbn');
      writeFileSync(good, bundle.swbn);
      assert.throws(() => crossVerify(good, webBundleId(rawPublicKey(newKey())), cli), /rejected/);
    } finally {
      temp.remove();
    }
  });
});
