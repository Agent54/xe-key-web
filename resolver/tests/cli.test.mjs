// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// bin/keyweb-resolve.mjs, exercised as a real subprocess.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64url, pinFor } from '../src/index.mjs';
import { makePublisher, makeApp } from '../src/fixtures.mjs';

const CLI = fileURLToPath(new URL('../bin/keyweb-resolve.mjs', import.meta.url));
const K_ED = 'mix2p32okr3zpmwz3pily6bmbjlfrjvpyzljdkc4mzvpkb6lf2mqaaic';

function run(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function fixtureFile(dir, name, pub, slug, appId, { did = pub.did } = {}) {
  const file = path.join(dir, name);
  const entry = { pdoc: base64url.encode(pub.pdoc()), rec: base64url.encode(pub.app(slug, appId)), railId: did };
  fs.writeFileSync(file, JSON.stringify({ rails: { at: { [`${pub.handle}|${slug}`]: entry } } }));
  return file;
}

test('cli: usage, parse, pin and inspect', () => {
  assert.equal(run([]).code, 1);
  const help = run(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, /keyweb-resolve resolve <url>/);

  const parsed = run(['parse', 'key-web://cool-site.alice.dht/x#:~:pin=e4g5saaasdl6ahelvnt4', '--json']);
  assert.equal(parsed.code, 0);
  const json = JSON.parse(parsed.out);
  assert.deepEqual([json.kind, json.slug, json.publisher, json.rail, json.pin], ['name', 'cool-site', 'alice', 'dht', 'e4g5saaasdl6ahelvnt4']);
  assert.equal(run(['parse', 'key-web://cool-site.alice/']).code, 2);

  assert.equal(run(['pin', K_ED]).out.trim(), 'e4g5saaasdl6ahelvnt4');
  assert.equal(run(['pin', K_ED, '--length', '16']).out.trim(), 'e4g5saaasdl6ahel');
  assert.equal(run(['pin', 'nope']).code, 1);

  const pub = makePublisher('cli-inspect', { profile: 'K-ED' });
  const inspected = run(['inspect', base64url.encode(pub.pdoc())]);
  assert.equal(inspected.code, 0);
  assert.equal(JSON.parse(inspected.out).t, 'kw-publisher/1');
});

test('cli: resolve with fixtures, TOFU store, pins and hijack exit codes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyweb-cli-'));
  try {
    const alice = makePublisher('alice', { profile: 'K-ED', rails: ['at'] });
    const app = makeApp('cli-app').id;
    const good = fixtureFile(dir, 'good.json', alice, 'cool-site', app);
    const store = path.join(dir, 'trust.json');

    const ok = run(['resolve', 'key-web://cool-site.alice.example/a', '--fixtures', good, '--store', store, '--json']);
    assert.equal(ok.code, 0, ok.err);
    const result = JSON.parse(ok.out);
    assert.equal(result.canonicalUrl, `key-web://${app}.key/a`);
    assert.equal(result.status, 'first-use');

    const human = run(['resolve', 'key-web://cool-site.alice.example/', '--fixtures', good, '--store', store]);
    assert.equal(human.code, 0);
    assert.match(human.out, /^OK {2}known/);

    const wrongPin = run(['resolve', `key-web://cool-site.alice.example/#:~:pin=${pinFor(makeApp('x').id)}`, '--fixtures', good]);
    assert.equal(wrongPin.code, 3);
    assert.match(wrongPin.out, /FAIL-CLOSED {2}PIN_MISMATCH/);

    const mallory = makePublisher('mallory', { profile: 'K-ED', handle: 'alice.example', rails: ['at'] });
    const evil = fixtureFile(dir, 'evil.json', mallory, 'cool-site', makeApp('evil').id);
    const hijack = run(['resolve', 'key-web://cool-site.alice.example/', '--fixtures', evil, '--store', store, '--json']);
    assert.equal(hijack.code, 3);
    assert.equal(JSON.parse(hijack.out).code, 'HANDLE_HIJACK');

    const none = run(['resolve', 'key-web://cool-site.alice.example/']);
    assert.equal(none.code, 2, 'no rails configured: unresolvable, not a security refusal');
    assert.equal(run(['resolve', `key-web://${K_ED}.key/`]).code, 0, 'key URLs need no rail');
    assert.equal(run(['resolve', 'x', '--fixtures', good, '--live']).code, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('cli: the offline demo passes every check', () => {
  const demo = run(['demo', '--json']);
  assert.equal(demo.code, 0, demo.err);
  const report = JSON.parse(demo.out);
  assert.ok(report.total >= 10);
  assert.equal(report.passed, report.total);
});
