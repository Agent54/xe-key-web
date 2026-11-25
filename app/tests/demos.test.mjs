// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The demo apps as sources: what each one ships, declares and asks for.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { CAPABILITIES } from '../runner/src/capabilities.js';
import { DEMOS_DIR, DEMO_BUILDS, RUNNER_DIR, SHARED_FILES, demoFiles, runnerFiles } from '../scripts/lib/site.mjs';

const SOURCES = ['localpad', 'leakytracker', 'peersync-calc'];
const text = (...parts) => readFileSync(join(DEMOS_DIR, ...parts), 'utf8');
const json = (...parts) => JSON.parse(text(...parts));

describe('every demo app', () => {
  for (const source of SOURCES) {
    test(`${source}: ships an entry point, a manifest, a descriptor, an icon and the shared files`, () => {
      const files = demoFiles(source);
      for (const path of ['index.html', 'app.js', 'app.css', 'icon-192.png', 'cover.png', '.well-known/manifest.webmanifest', '.well-known/key-web.json', ...SHARED_FILES]) {
        assert.ok(files.has(path), `${source} has no ${path}`);
      }
      assert.equal(files.size, 9);
    });

    test(`${source}: manifest and descriptor agree, and declare only capabilities the runner brokers`, () => {
      const manifest = json(source, '.well-known', 'manifest.webmanifest');
      const descriptor = json(source, '.well-known', 'key-web.json');
      assert.equal(descriptor.key_web, 1);
      assert.equal(descriptor.name, manifest.name);
      assert.equal(descriptor.version, manifest.version);
      assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
      assert.equal(manifest.start_url, '/');
      assert.equal(manifest.icons[0].src, '/icon-192.png');
      for (const capability of descriptor.capabilities) assert.ok(Object.hasOwn(CAPABILITIES, capability), capability);
      // The commitment to the next key is added by the build, never written by hand.
      assert.equal(descriptor.next_key_digest, undefined);
    });

    test(`${source}: its page loads only its own files`, () => {
      const page = text(source, 'index.html');
      const references = [...page.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
      assert.ok(references.length >= 4);
      const files = demoFiles(source);
      for (const reference of references) {
        assert.ok(!/^[a-z][a-z0-9+.-]*:|^\/\//i.test(reference), `${source} references ${reference}`);
        assert.ok(files.has(reference), `${source} references a file it does not ship: ${reference}`);
      }
      assert.match(page, /<script type="module" src="app\.js"><\/script>/);
    });
  }
});

describe('what each app is for', () => {
  test('LocalPad asks for nothing and never touches the network', () => {
    const code = text('localpad', 'app.js');
    assert.deepEqual(json('localpad', '.well-known', 'key-web.json').capabilities, []);
    for (const api of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'runner.request', 'runner.invoke']) assert.ok(!code.includes(api), api);
    assert.match(code, /localStorage\.setItem\(STORAGE_KEY/);
  });

  test('LeakyTracker makes exactly five attempts, over five different channels, and declares nothing', () => {
    const code = text('leakytracker', 'app.js');
    const idsIn = (name) => {
      const block = code.slice(code.indexOf(`const ${name} = [`), code.indexOf('\n];', code.indexOf(`const ${name} = [`)));
      return [...block.matchAll(/^\s{4}id: '([a-z]+)',$/gm)].map((match) => match[1]);
    };
    assert.deepEqual(idsIn('ATTACKS'), ['fetch', 'img', 'beacon', 'websocket', 'form']);
    // Kept apart from the five: the two channels no page policy closes.
    assert.deepEqual(idsIn('GAPS'), ['webrtc', 'preconnect']);
    for (const api of ['fetch(url', 'new Image()', 'navigator.sendBeacon(', 'new WebSocket(', 'form.submit()']) assert.ok(code.includes(api), api);
    assert.deepEqual(json('leakytracker', '.well-known', 'key-web.json').capabilities, []);
    assert.match(code, /securitypolicyviolation/);
  });

  test('PeerSync Calc declares two capabilities and reaches the network only through the runner', () => {
    const code = text('peersync-calc', 'app.js');
    assert.deepEqual(json('peersync-calc', '.well-known', 'key-web.json').capabilities, ['net:sync-relay', 'storage:export']);
    for (const api of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon']) assert.ok(!code.includes(api), api);
    assert.match(code, /runner\.request\(capability, reason\)/);
    assert.match(code, /runner\.invoke\(capability, args\)/);
  });

  test('the shared client only ever talks to the runner, by its exact origin', () => {
    const code = text('shared', 'keyweb-client.js');
    assert.match(code, /window\.parent\.postMessage\(\{ keyweb: 1, \.\.\.message \}, RUNNER\)/);
    assert.match(code, /event\.origin !== RUNNER \|\| event\.source !== window\.parent/);
    assert.ok(!code.includes("'*'"));
  });
});

describe('what is built from them', () => {
  test('five builds from three sources, each under its own key name', () => {
    assert.equal(DEMO_BUILDS.length, 5);
    assert.equal(new Set(DEMO_BUILDS.map((build) => build.key)).size, 5);
    assert.deepEqual([...new Set(DEMO_BUILDS.map((build) => build.source))].sort(), [...SOURCES].sort());
    assert.deepEqual(DEMO_BUILDS.filter((build) => build.role === 'app').map((build) => build.slug), ['localpad', 'leakytracker', 'peersync-calc']);
    const first = DEMO_BUILDS.find((build) => build.slug === 'localpad' && build.role === 'app');
    const successor = DEMO_BUILDS.find((build) => build.role === 'successor');
    // The successor is signed by the very key the original committed to.
    assert.equal(first.nextKey, successor.key);
    assert.equal(DEMO_BUILDS.find((build) => build.role === 'impostor').source, 'localpad');
  });

  test('the runner ships its page, its engine and its loader', () => {
    const files = runnerFiles();
    for (const path of ['index.html', 'app.css', 'icon.svg', 'icon-256.png', '.well-known/manifest.webmanifest', 'src/main.js', 'src/engine/swbn.js', 'src/engine/cbor.js', 'src/engine/rotation.js', 'src/engine/chunks.js', 'src/engine/policy.js', 'loader/loader.html', 'loader/loader.js', 'loader/sw.js']) {
      assert.ok(files.has(path), path);
    }
    const page = readFileSync(join(RUNNER_DIR, 'index.html'), 'utf8');
    assert.match(page, /<script type="module" src="src\/main\.js"><\/script>/);
    assert.ok(!/<iframe/i.test(page), 'frames are only ever created by the sandbox, at run time');
  });
});
