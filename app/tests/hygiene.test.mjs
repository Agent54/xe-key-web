// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The hygiene gate: the tree is clean, and every rule bites.
//
// Everything the gate looks for is assembled from fragments here, so this
// file passes the gate too.

import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { KEY_FILE, listRepo, scanRepo, scanText } from '../scripts/hygiene-check.mjs';
import { tempDir } from './helpers.mjs';

const rules = (text) => scanText('x.md', text).map((finding) => finding.rule);
const web = 'ht' + 'tps://';
const at = '@';

describe('this repository', () => {
  const result = scanRepo();

  test('has no findings', () => {
    assert.deepEqual(result.findings, []);
    assert.ok(result.files.length >= 55, `only ${result.files.length} files were scanned`);
  });

  test('is scanned whole, but not its build output', () => {
    const paths = listRepo().map((file) => file.path);
    for (const expected of ['README.md', 'LICENSE', 'package.json', '.gitignore', '.forgejo/workflows/ci.yml', 'runner/index.html', 'demos/localpad/app.js', 'scripts/serve.mjs', 'tests/hygiene.test.mjs']) { // fg-gate-allow: CI workflow path test
      assert.ok(paths.includes(expected), `${expected} was not scanned`);
    }
    assert.ok(!paths.some((path) => path.startsWith('dist/') || path.startsWith('node_modules/') || path.startsWith('.git/')));
    assert.ok(!paths.some((path) => KEY_FILE.test(path)));
  });
});

describe('rules', () => {
  test('private, carrier-grade and link-local addresses', () => {
    for (const address of ['10.0.0' + '.5', '192.168' + '.1.20', '172.16' + '.0.1', '172.31' + '.255.254', '169.254' + '.10.10', '100.64' + '.0.1', '100.127' + '.1.1']) {
      assert.ok(rules(`host ${address} port 80`).includes('private-ip'), address);
    }
    for (const fine of ['127.0.0.1', '8.8.8.8', '172.32.0.1', '100.128.0.1', '1.10.0.0', 'version 10.2.3']) assert.ok(!rules(fine).includes('private-ip'), fine);
  });

  test('home-folder paths', () => {
    assert.ok(rules('/Us' + 'ers/someone/project').includes('home-path'));
    assert.ok(rules('/ho' + 'me/someone/.config').includes('home-path'));
    assert.ok(rules('C:\\Us' + 'ers\\someone').includes('home-path'));
    assert.deepEqual(rules('~/.keys/ and /tmp/work and ./scripts'), []);
  });

  test('internal host names, but not localhost', () => {
    for (const name of ['build.co' + 'rp', 'nas.l' + 'an', 'printer.loc' + 'al', 'git.inter' + 'nal', 'box.tail1234.ts.n' + 'et', 'router.home.ar' + 'pa']) {
      assert.ok(rules(`see ${name} for details`).includes('internal-host'), name);
    }
    assert.deepEqual(rules('http://peer-1.localhost:5761/ and tracker.localhost and localhost'), []);
  });

  test('a key-web address is not a host, whatever rail it ends in', () => {
    // The petname rail ends in the same label as a private network name.
    assert.deepEqual(rules('open key-web://trusted-notes.local/ or key-web://localpad.lukeinth.at/ or KEY-WEB://Pad.Local/notes'), []);
    // Only inside the address: the same name anywhere else is still caught.
    assert.ok(rules('key-web://pad.loc' + 'al/ is served by nas.loc' + 'al').includes('internal-host'));
    assert.ok(rules('see printer.loc' + 'al, not key-web://x.y.at/').includes('internal-host'));
    assert.ok(rules('web://nas.loc' + 'al/').includes('internal-host'));
  });

  test('e-mail addresses', () => {
    assert.ok(rules(`mail someone${at}example.org`).includes('email'));
    assert.deepEqual(rules('uses: actions/checkout' + at + 'v4 and node' + at + '24'), []);
  });

  test('key material, tokens and hard-coded credentials', () => {
    assert.ok(rules('-----BEGIN PRIV' + 'ATE KEY-----').includes('private-key'));
    assert.ok(rules('-----BEGIN OPENSSH PRIV' + 'ATE KEY-----').includes('private-key'));
    assert.ok(rules('AK' + 'IA' + 'ABCDEFGHIJKLMNOP').includes('token'));
    assert.ok(rules('gh' + 'p_' + 'a'.repeat(36)).includes('token'));
    assert.ok(rules('pass' + 'word = "hunter2hunter2"').includes('credential'));
    assert.ok(rules('api_' + "key: 'abcdefgh12345678'").includes('credential'));
    assert.deepEqual(rules('-----BEGIN PUBLIC KEY----- and the word password and a secret planted in storage'), []);
  });

  test('names from the workspace this was written in', () => {
    for (const name of ['anti' + 'gravity', 'gem' + 'ini', 'silver' + 'moon', 'wave9' + 'e-something']) assert.ok(rules(`built in ${name}`).includes('workspace-name'), name);
    assert.deepEqual(rules('a wave of requests, and waves 1-3'), []);
  });

  test('hosts that are not loopback or allow-listed', () => {
    for (const url of [`${web}example.org/x`, 'ht' + 'tp://cdn.example.net:8080/a.js', 'ws' + 's://feed.example.io/socket', `${web}localhost.example.org/`, 'ht' + 'tp://cdn.example.net:8080;']) {
      assert.ok(rules(`fetch(${JSON.stringify(url)})`).includes('host'), url);
    }
    const fine = [
      'http://localhost:5760/', 'http://127.0.0.1:5760/', 'http://[::1]:5760/', 'http://tracker.localhost:5761/collect', 'ws://tracker.localhost:5761/ws',
      'http://*.localhost:5760', `${web}www.w3.org/2000/svg`, `${web}data.forgejo.org/actions/checkout`, 'key-web://abc/', 'isolated-app://abc/', // fg-gate-allow: CI action URL test
      'http://${id}.localhost:${port}/', 'http://localhost:${ports.app}',
      // A port followed by the punctuation of a policy or a sentence.
      'frame-ancestors http://localhost:5760; next', 'see http://localhost:5760.', 'http://localhost:5760, then',
    ];
    for (const url of fine) assert.deepEqual(rules(`open ${url} now`), [], url);
  });

  test('findings carry the file, the line and what was found', () => {
    const [finding] = scanText('docs/x.md', `line one\nline two\nmail someone${at}example.org\n`);
    assert.deepEqual({ path: finding.path, line: finding.line, rule: finding.rule }, { path: 'docs/x.md', line: 3, rule: 'email' });
  });
});

describe('scanning a tree', () => {
  test('flags key-like files, symlinks and text findings, and skips build output', () => {
    const temp = tempDir();
    try {
      mkdirSync(join(temp.dir, 'src'));
      mkdirSync(join(temp.dir, 'dist'));
      mkdirSync(join(temp.dir, 'node_modules'));
      writeFileSync(join(temp.dir, 'README.md'), 'clean\n');
      writeFileSync(join(temp.dir, 'src', 'signing.pem'), 'x');
      writeFileSync(join(temp.dir, 'src', '.env'), 'x');
      writeFileSync(join(temp.dir, 'src', 'id_ed25519'), 'x');
      writeFileSync(join(temp.dir, 'src', 'notes.md'), `mail someone${at}example.org\n`);
      writeFileSync(join(temp.dir, 'src', 'image.png'), `someone${at}example.org`);
      writeFileSync(join(temp.dir, 'dist', 'leak.md'), `someone${at}example.org`);
      writeFileSync(join(temp.dir, 'node_modules', 'leak.md'), `someone${at}example.org`);
      symlinkSync(join(temp.dir, 'README.md'), join(temp.dir, 'src', 'link.md'));
      const result = scanRepo(temp.dir);
      assert.deepEqual(result.findings.map((finding) => `${finding.path}:${finding.rule}`).sort(), [
        'src/.env:key-file', 'src/id_ed25519:key-file', 'src/link.md:symlink', 'src/notes.md:email', 'src/signing.pem:key-file',
      ]);
    } finally {
      temp.remove();
    }
  });

  test('knows a key file by its name', () => {
    for (const name of ['key.pem', 'a/b/server.key', 'cert.p12', 'store.jks', '.env', '.env.production', 'id_rsa', 'deep/id_ecdsa', 'x.pfx', 'x.p8', 'release.keystore']) assert.ok(KEY_FILE.test(name), name);
    for (const name of ['keys.md', 'monkey.js', 'env.js', 'pem.txt', 'key-web.json', 'README.md']) assert.ok(!KEY_FILE.test(name), name);
  });
});
