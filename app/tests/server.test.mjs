// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The two loopback servers: who they answer to, what they send, and that
// "kill all servers" really closes sockets.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { connect } from 'node:net';
import { after, before, describe, test } from 'node:test';
import { MAX_RELAY_BYTES } from '../runner/src/config.js';
import { checkManifest, swarmDownload } from '../runner/src/engine/chunks.js';
import { verifyNameRecord } from '../runner/src/engine/names.js';
import { WORKER_CSP, loaderCsp, runnerCsp } from '../runner/src/engine/policy.js';
import { verifySwbn } from '../runner/src/engine/swbn.js';
import { startServers } from '../scripts/serve.mjs';
import { builtDemos, request } from './helpers.mjs';

let demos;
let servers;
let app;
let net;
let pad;

before(async () => {
  demos = await builtDemos();
  servers = await startServers({ appPort: 0, mirrorPort: 0, bundlesDir: demos.dir });
  app = servers.appPort;
  net = servers.mirrorPort;
  pad = demos.find('localpad');
});

after(async () => {
  await servers.close();
  demos.remove();
});

const portOpen = (port) => new Promise((done) => {
  const socket = connect({ host: '127.0.0.1', port });
  socket.once('connect', () => {
    socket.destroy();
    done(true);
  });
  socket.once('error', () => done(false));
});

describe('the browser port', () => {
  test('serves the runner under its strict policy', async () => {
    const page = await request(app, { path: '/' });
    assert.equal(page.status, 200);
    assert.match(page.headers['content-type'], /^text\/html/);
    assert.equal(page.headers['content-security-policy'], runnerCsp({ appPort: app, mirrorPort: net }));
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    assert.equal(page.headers['referrer-policy'], 'no-referrer');
    assert.equal(page.headers['cross-origin-opener-policy'], 'same-origin');
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.match(page.text, /<title>KeyWeb Runner<\/title>/);
    for (const path of ['/app.css', '/src/main.js', '/src/engine/swbn.js', '/icon.svg', '/icon-256.png', '/.well-known/manifest.webmanifest']) {
      assert.equal((await request(app, { path })).status, 200, path);
    }
    assert.equal((await request(app, { path: '/', method: 'HEAD' })).body.length, 0);
  });

  test('answers only to localhost and to well-formed key origins', async () => {
    for (const host of ['127.0.0.1', 'example.test', 'localhost.example.test', 'evil.localhost', 'peer-1.localhost', `${'a'.repeat(56)}.localhost`, `${pad.id}.localhost.example.test`, `x.${pad.id}.localhost`]) {
      const answer = await request(app, { host, path: '/' });
      assert.equal(answer.status, 421, host);
    }
    assert.equal((await request(app, { path: '/', headers: { Host: '' } })).status, 421);
  });

  test('cannot be walked out of, and does not serve hidden files', async () => {
    for (const path of ['/../package.json', '/%2e%2e/package.json', '/..%2fpackage.json', '/src/../../package.json', '/%2e%2e%2f%2e%2e%2fLICENSE', '/.gitignore', '/.git/config', '/src/%00']) {
      const answer = await request(app, { path });
      assert.ok([400, 404].includes(answer.status), `${path} gave ${answer.status}`);
      assert.ok(!answer.text.includes('keyweb-runner'), path);
    }
    assert.equal((await request(app, { path: '/%' })).status, 400);
    assert.equal((await request(app, { path: '/nope.js' })).status, 404);
  });

  test('refuses to be written to', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const answer = await request(app, { path: '/index.html', method, body: 'x' });
      assert.equal(answer.status, 405, method);
      assert.equal(answer.headers.allow, 'GET, HEAD');
    }
  });

  test('serves the demo bundles it ships with, and they verify', async () => {
    const catalog = (await request(app, { path: '/demo-bundles/catalog.json' })).json();
    assert.equal(catalog.apps.length, 5);
    const bundle = await request(app, { path: `/demo-bundles/${pad.file}` });
    assert.equal(bundle.status, 200);
    assert.equal((await verifySwbn(new Uint8Array(bundle.body), { expectedId: pad.id })).id, pad.id);
    assert.equal((await request(app, { path: '/demo-bundles/rotation/valid.json' })).json().format, 'key-web-rotation/1');
    assert.equal((await request(app, { path: '/demo-bundles/../build-info.json' })).status, 404);
  });

  test('gives a key origin its loader and worker, and nothing else', async () => {
    const host = `${pad.id}.localhost`;
    const runner = `http://localhost:${app}`;
    const loader = await request(app, { host, path: '/__keyweb/loader.html' });
    assert.equal(loader.status, 200);
    assert.equal(loader.headers['content-security-policy'], loaderCsp({ runnerOrigin: runner }));
    for (const path of ['/__keyweb/loader.js', '/__keyweb/loader.css', '/__keyweb/engine/swbn.js', '/__keyweb/engine/cbor.js', '/__keyweb/engine/bytes.js', '/__keyweb/engine/policy.js']) {
      assert.equal((await request(app, { host, path })).status, 200, path);
    }
    const worker = await request(app, { host, path: '/__keyweb/sw.js' });
    assert.equal(worker.status, 200);
    assert.equal(worker.headers['service-worker-allowed'], '/');
    assert.equal(worker.headers['content-security-policy'], WORKER_CSP);
    assert.match(worker.headers['content-type'], /^text\/javascript/);
    // Not the runner's files, not the bundle, not anything outside the two folders.
    for (const path of ['/', '/index.html', '/app.js', '/src/main.js', '/api/network', '/demo-bundles/catalog.json', '/__keyweb/', '/__keyweb/engine/../../main.js', '/__keyweb/engine/..%2f..%2fmain.js', '/__keyweb/main.js']) {
      const answer = await request(app, { host, path });
      assert.equal(answer.status, 404, path);
      assert.equal(answer.headers['content-security-policy'], loaderCsp({ runnerOrigin: runner }));
    }
    assert.equal((await request(app, { host, path: '/__keyweb/loader.html', method: 'POST', body: 'x' })).status, 405);
  });

  test('only the runner page may pull the plug', async () => {
    const origin = `http://localhost:${app}`;
    const attempts = [
      {},
      { Origin: origin },
      { 'X-KeyWeb-Control': '1' },
      { Origin: `http://localhost:${net}`, 'X-KeyWeb-Control': '1' },
      { Origin: 'null', 'X-KeyWeb-Control': '1' },
      { Origin: `http://${pad.id}.localhost:${app}`, 'X-KeyWeb-Control': '1' },
    ];
    for (const headers of attempts) {
      const answer = await request(app, { path: '/api/network/kill', method: 'POST', headers });
      assert.equal(answer.status, 403, JSON.stringify(headers));
    }
    assert.equal((await request(app, { path: '/api/network/kill' })).status, 404);
    assert.equal(servers.networkUp(), true);
    assert.equal((await request(app, { host: `${pad.id}.localhost`, path: '/api/network/kill', method: 'POST', headers: { Origin: origin, 'X-KeyWeb-Control': '1' } })).status, 405);
    assert.equal(servers.networkUp(), true);
  });

  test('kill closes every socket on the network port, revive reopens it', async () => {
    const control = { Origin: `http://localhost:${app}`, 'X-KeyWeb-Control': '1' };
    assert.equal(await portOpen(net), true);
    assert.deepEqual((await request(app, { path: '/api/network' })).json(), { up: true, mirrorPort: net, control: true });
    const killed = await request(app, { path: '/api/network/kill', method: 'POST', headers: control });
    assert.equal(killed.json().up, false);
    assert.equal(await portOpen(net), false);
    await assert.rejects(request(net, { path: `/mirrors/${pad.file}` }), /ECONNREFUSED/);
    assert.equal((await request(app, { path: '/api/network' })).json().up, false);
    // The browser itself is untouched.
    assert.equal((await request(app, { path: '/' })).status, 200);
    // Killing twice is harmless.
    assert.equal((await request(app, { path: '/api/network/kill', method: 'POST', headers: control })).json().up, false);
    const revived = await request(app, { path: '/api/network/revive', method: 'POST', headers: control });
    assert.equal(revived.json().up, true);
    assert.equal(revived.json().mirrorPort, net);
    assert.equal(await portOpen(net), true);
    assert.equal((await request(net, { path: `/mirrors/${pad.file}` })).status, 200);
  });

  test('collects policy reports from key origins and hands them to the runner', async () => {
    const before = (await request(app, { path: '/api/telemetry?since=0' })).json().seq;
    const report = JSON.stringify({ 'csp-report': { 'document-uri': `http://${pad.id}.localhost:${app}/`, 'effective-directive': 'connect-src', 'blocked-uri': 'http://tracker.localhost/collect?x=1' } });
    assert.equal((await request(app, { path: `/api/csp-report?o=${pad.id}`, method: 'POST', headers: { 'Content-Type': 'application/csp-report' }, body: report })).status, 204);
    // Ignored: no key, a bad key, not JSON, too large.
    assert.equal((await request(app, { path: '/api/csp-report', method: 'POST', body: report })).status, 204);
    assert.equal((await request(app, { path: '/api/csp-report?o=nope', method: 'POST', body: report })).status, 204);
    assert.equal((await request(app, { path: `/api/csp-report?o=${pad.id}`, method: 'POST', body: '{' })).status, 204);
    assert.equal((await request(app, { path: `/api/csp-report?o=${pad.id}`, method: 'POST', body: 'x'.repeat(40000) })).status, 204);
    const telemetry = (await request(app, { path: `/api/telemetry?since=${before}` })).json();
    assert.equal(telemetry.seq, before + 1);
    assert.equal(telemetry.events.length, 1);
    assert.deepEqual({ id: telemetry.events[0].id, directive: telemetry.events[0].directive, blocked: telemetry.events[0].blocked }, { id: pad.id, directive: 'connect-src', blocked: 'http://tracker.localhost/collect?x=1' });
    assert.equal((await request(app, { path: `/api/telemetry?since=${telemetry.seq}` })).json().events.length, 0);
    assert.equal((await request(app, { path: '/api/unknown' })).status, 404);
  });
});

describe('the network port', () => {
  test('answers only to the names of its five roles', async () => {
    for (const host of ['127.0.0.1', 'example.test', 'peer-0.localhost', 'peer-5.localhost', 'peer-12.localhost', 'mirror.localhost', `${pad.id}.localhost`, 'tracker.localhost.example.test']) {
      assert.equal((await request(net, { host, path: '/' })).status, 421, host);
    }
  });

  test('the mirror hands out signed bundles to anyone, and nothing else', async () => {
    const bundle = await request(net, { path: `/mirrors/${pad.file}` });
    assert.equal(bundle.status, 200);
    assert.equal(bundle.headers['access-control-allow-origin'], '*');
    assert.equal(bundle.headers['content-type'], 'application/octet-stream');
    assert.match(bundle.headers['content-disposition'], /^attachment; filename="localpad-1\.0\.0\.swbn"$/);
    assert.equal(createHash('sha256').update(bundle.body).digest('hex'), pad.sha256);
    assert.equal((await verifySwbn(new Uint8Array(bundle.body), { expectedId: pad.id })).ok, true);
    for (const path of ['/mirrors/', '/mirrors/catalog.json', '/mirrors/nope.swbn', '/mirrors/../catalog.json', '/mirrors/rotation/valid.json', '/']) {
      assert.equal((await request(net, { path })).status, 404, path);
    }
    assert.equal((await request(net, { path: `/mirrors/${pad.file}`, method: 'POST', body: 'x' })).status, 405);
  });

  test('peers announce a chunk list for a key and serve chunks by hash', async () => {
    const manifest = checkManifest((await request(net, { host: 'peer-1.localhost', path: `/swarm/announce/${pad.id}` })).json(), { maxBytes: 32 * 1024 * 1024 });
    assert.deepEqual(manifest, pad.manifest);
    assert.ok(manifest.chunks.length >= 6, 'the demo bundle should span several chunks');
    const chunk = await request(net, { host: 'peer-3.localhost', path: `/swarm/chunk/${manifest.chunks[2]}` });
    assert.equal(chunk.status, 200);
    assert.equal(chunk.headers['x-peer'], 'peer-3');
    assert.equal(createHash('sha256').update(chunk.body).digest('hex'), manifest.chunks[2]);
    assert.equal((await request(net, { host: 'peer-1.localhost', path: `/swarm/announce/${'a'.repeat(52)}aaic` })).status, 404);
    assert.equal((await request(net, { host: 'peer-1.localhost', path: `/swarm/chunk/${'0'.repeat(64)}` })).status, 404);
    assert.equal((await request(net, { host: 'peer-1.localhost', path: `/mirrors/${pad.file}` })).status, 404);
  });

  test('a poisoned peer serves the right length and the wrong bytes, and a real download survives it', async () => {
    const manifest = pad.manifest;
    const poisoned = await request(net, { host: 'peer-2.localhost', path: `/swarm/chunk/${manifest.chunks[1]}?poison=1` });
    assert.equal(poisoned.status, 200);
    assert.equal(poisoned.body.length, manifest.chunkSize);
    assert.notEqual(createHash('sha256').update(poisoned.body).digest('hex'), manifest.chunks[1]);

    const events = [];
    const fetchChunk = async (peer, hash) => new Uint8Array((await request(net, { host: `peer-${peer + 1}.localhost`, path: `/swarm/chunk/${hash}${peer === 1 ? '?poison=1' : ''}` })).body);
    const { bytes, stats } = await swarmDownload({ manifest, peers: 4, fetchChunk, onEvent: (event) => events.push(event) });
    assert.equal(createHash('sha256').update(bytes).digest('hex'), pad.sha256);
    assert.equal((await verifySwbn(bytes, { expectedId: pad.id })).ok, true);
    assert.equal(stats.poisoned, 1);
    assert.deepEqual(stats.banned, [1]);
    const bad = events.find((event) => event.status === 'poisoned');
    assert.equal(events.find((event) => event.index === bad.index && event.status === 'ok').peer, 2);
  });

  test('the relay stores one slot per key, for the runner only', async () => {
    const host = 'relay.localhost';
    const path = `/sync/${pad.id}`;
    const origin = `http://localhost:${app}`;
    const empty = await request(net, { host, path });
    assert.equal(empty.status, 200);
    assert.equal(empty.json().data, null);
    assert.equal(empty.headers['access-control-allow-origin'], origin);
    const preflight = await request(net, { host, path, method: 'OPTIONS' });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers['access-control-allow-methods'], 'GET, PUT');
    const put = await request(net, { host, path, method: 'PUT', body: '{"tape":["6 × 7 = 42"]}' });
    assert.deepEqual({ ok: put.json().ok, version: put.json().version }, { ok: true, version: 1 });
    assert.equal((await request(net, { host, path, method: 'PUT', body: 'second' })).json().version, 2);
    assert.equal((await request(net, { host, path })).json().data, 'second');
    // Another key's slot is another slot.
    assert.equal((await request(net, { host, path: `/sync/${demos.find('peersync-calc').id}` })).json().data, null);
    assert.equal((await request(net, { host, path, method: 'PUT', body: 'x'.repeat(MAX_RELAY_BYTES + 1) })).status, 413);
    assert.equal((await request(net, { host, path: '/sync/not-a-key' })).status, 404);
    assert.equal((await request(net, { host, path, method: 'DELETE' })).status, 405);
  });

  test('the tracker counts every request and byte it receives, WebSockets included', async () => {
    const host = 'tracker.localhost';
    const start = { requests: servers.ledger.requests, bytes: servers.ledger.bytes };
    const pixel = await request(net, { host, path: '/collect?via=img&secret=abc' });
    assert.equal(pixel.status, 200);
    assert.equal(pixel.headers['content-type'], 'image/png');
    assert.deepEqual([...pixel.body.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47]);
    await request(net, { host, path: '/collect?via=beacon', method: 'POST', body: 'secret=abcdef' });
    assert.equal(servers.ledger.requests - start.requests, 2);
    assert.equal(servers.ledger.bytes - start.bytes, 'via=img&secret=abc'.length + 'via=beacon'.length + 'secret=abcdef'.length);

    const handshake = await new Promise((done, fail) => {
      const socket = connect({ host: '127.0.0.1', port: net });
      let text = '';
      socket.on('data', (part) => {
        text += part.toString('latin1');
      });
      socket.on('close', () => done(text));
      socket.on('error', fail);
      socket.write(`GET /ws?via=websocket HTTP/1.1\r\nHost: tracker.localhost:${net}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    assert.match(handshake, /^HTTP\/1\.1 101 Switching Protocols/);
    // The accept value RFC 6455 gives for this sample key.
    assert.match(handshake, /Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK\+xOo=/);
    assert.equal(servers.ledger.requests - start.requests, 3);

    const stats = await request(net, { host, path: '/stats' });
    assert.equal(stats.json().requests, servers.ledger.requests);
    assert.equal(stats.headers['access-control-allow-origin'], `http://localhost:${app}`);
    assert.deepEqual(stats.json().recent.slice(-3).map((entry) => entry.via), ['img', 'beacon', 'websocket']);
    // A WebSocket to anything but the tracker is dropped.
    const refused = await new Promise((done) => {
      const socket = connect({ host: '127.0.0.1', port: net });
      let text = '';
      socket.on('data', (part) => {
        text += part;
      });
      socket.on('close', () => done(text));
      socket.on('error', () => done(text));
      socket.write(`GET /ws HTTP/1.1\r\nHost: localhost:${net}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    assert.equal(refused, '');
  });

  test('the tracker also counts what no page policy stops: UDP datagrams and bare connections', async () => {
    const start = { requests: servers.ledger.requests, bytes: servers.ledger.bytes, datagrams: servers.ledger.datagrams, connections: servers.ledger.connections };
    // A STUN binding request, as WebRTC sends it: 20 bytes over UDP.
    const stun = Buffer.concat([Buffer.from('000100002112a442', 'hex'), Buffer.alloc(12, 7)]);
    const udp = createSocket('udp4');
    await new Promise((done, fail) => udp.send(stun, net, '127.0.0.1', (error) => (error ? fail(error) : done())));
    // A preconnect: a TCP connection that is opened and never says anything.
    await new Promise((done) => {
      const socket = connect({ host: '127.0.0.1', port: net });
      socket.once('connect', () => socket.end());
      socket.once('close', done);
    });
    await new Promise((done) => setTimeout(done, 150));
    assert.equal(servers.ledger.datagrams - start.datagrams, 1);
    assert.equal(servers.ledger.bytes - start.bytes, 20);
    assert.equal(servers.ledger.requests - start.requests, 1);
    assert.equal(servers.ledger.connections - start.connections, 1);
    // A connection that does make a request is not a bare one.
    await request(net, { host: 'tracker.localhost', path: '/stats' });
    await new Promise((done) => setTimeout(done, 50));
    assert.equal(servers.ledger.connections - start.connections, 1);
    const stats = (await request(net, { host: 'tracker.localhost', path: '/stats' })).json();
    assert.equal(stats.datagrams, servers.ledger.datagrams);
    assert.equal(stats.connections, servers.ledger.connections);

    // Killed means killed for UDP too.
    await servers.kill();
    const before = servers.ledger.datagrams;
    await new Promise((done) => udp.send(stun, net, '127.0.0.1', () => done()));
    await new Promise((done) => setTimeout(done, 150));
    assert.equal(servers.ledger.datagrams, before);
    await servers.revive();
    await new Promise((done, fail) => udp.send(stun, net, '127.0.0.1', (error) => (error ? fail(error) : done())));
    await new Promise((done) => setTimeout(done, 150));
    assert.equal(servers.ledger.datagrams, before + 1);
    await new Promise((done) => udp.close(done));
  });

  test('the two resolver rails answer a name with a signed record, and both name the same key', async () => {
    const asked = { app: 'localpad', publisher: 'lukeinth' };
    const keys = [];
    for (const rail of ['at', 'dht']) {
      const answer = await request(net, { host: `rail-${rail}.localhost`, path: '/resolve/lukeinth/localpad' });
      assert.equal(answer.status, 200, rail);
      assert.equal(answer.headers['access-control-allow-origin'], '*');
      assert.equal(answer.headers['x-rail-mode'], 'normal');
      const checked = await verifyNameRecord(answer.json(), { ...asked, rail });
      assert.equal(checked.ok, true, rail);
      keys.push(checked.key);
    }
    assert.deepEqual(keys, [pad.id, pad.id]);
    // A record from one rail is not an answer on the other.
    const lifted = (await request(net, { host: 'rail-at.localhost', path: '/resolve/lukeinth/localpad' })).json();
    assert.equal((await verifyNameRecord(lifted, { ...asked, rail: 'dht' })).code, 'RECORD_WRONG_NAME');
    assert.equal((await verifyNameRecord((await request(net, { host: 'rail-dht.localhost', path: '/resolve/mallory/leaky' })).json(), { app: 'leaky', publisher: 'mallory', rail: 'dht' })).key, demos.find('leakytracker').id);
    for (const [host, path] of [
      ['rail-at.localhost', '/resolve/mallory/leaky'], ['rail-at.localhost', '/resolve/lukeinth/nope'], ['rail-at.localhost', '/resolve/lukeinth'],
      ['rail-at.localhost', '/resolve/../names/normal'], ['rail-at.localhost', '/resolve/lukeinth/..%2f..%2fcatalog'], ['rail-at.localhost', '/'],
    ]) {
      assert.equal((await request(net, { host, path })).status, 404, path);
    }
    assert.equal((await request(net, { host: 'rail-at.localhost', path: '/resolve/lukeinth/localpad', method: 'POST', body: 'x' })).status, 405);
    assert.equal((await request(net, { host: 'rail-key.localhost', path: '/resolve/lukeinth/localpad' })).status, 421);
  });

  test('a rail can be killed on its own, hijacked, or made to publish a rotation, and only by the runner', async () => {
    const control = { Origin: `http://localhost:${app}`, 'X-KeyWeb-Control': '1', 'Content-Type': 'application/json' };
    const set = (wish, headers = control) => request(app, { path: '/api/rails', method: 'POST', headers, body: JSON.stringify(wish) });
    const resolve = (rail, name = 'localpad') => request(net, { host: `rail-${rail}.localhost`, path: `/resolve/lukeinth/${name}` });
    const honest = { at: { down: false, mode: 'normal' }, dht: { down: false, mode: 'normal' } };
    assert.deepEqual((await request(app, { path: '/api/rails' })).json(), { rails: honest, control: true });

    // Nobody but the runner page may touch a rail.
    for (const headers of [{}, { Origin: control.Origin }, { 'X-KeyWeb-Control': '1' }, { Origin: `http://${pad.id}.localhost:${app}`, 'X-KeyWeb-Control': '1' }]) {
      assert.equal((await set({ rail: 'at', mode: 'hijacked' }, headers)).status, 403);
    }
    assert.equal((await set({ rail: 'key', down: true })).status, 400);
    assert.equal((await set({ rail: 'at', mode: 'evil' })).status, 400);
    assert.equal((await set({ rail: '__proto__', down: true })).status, 400);
    assert.equal((await request(app, { path: '/api/rails', method: 'POST', headers: control, body: '{' })).status, 400);
    assert.deepEqual(servers.rails, honest);

    // Down: the connection is dropped. The other rail is unaffected.
    assert.equal((await set({ rail: 'at', down: true })).json().rails.at.down, true);
    await assert.rejects(resolve('at'), /socket hang up|ECONNRESET/);
    assert.equal((await resolve('dht')).status, 200);
    await set({ rail: 'at', down: false });
    assert.equal((await resolve('at')).status, 200);

    // Hijacked: the same name, a validly signed record, a different key and a different signer.
    const before = await verifyNameRecord((await resolve('at')).json(), { app: 'localpad', publisher: 'lukeinth', rail: 'at' });
    await set({ rail: 'at', mode: 'hijacked' });
    const answer = await resolve('at');
    assert.equal(answer.headers['x-rail-mode'], 'hijacked');
    const hijacked = await verifyNameRecord(answer.json(), { app: 'localpad', publisher: 'lukeinth', rail: 'at' });
    assert.equal(hijacked.ok, true);
    assert.equal(hijacked.key, demos.catalog.apps.find((entry) => entry.role === 'impostor').id);
    assert.notDeepEqual([...hijacked.publisherKey], [...before.publisherKey]);
    assert.equal((await verifyNameRecord((await resolve('at', 'peersync')).json(), { app: 'peersync', publisher: 'lukeinth', rail: 'at' })).key, hijacked.key);
    // The hijack is of one handle on one rail.
    assert.equal((await verifyNameRecord((await resolve('dht')).json(), { app: 'localpad', publisher: 'lukeinth', rail: 'dht' })).key, pad.id);

    // Rotated: the successor's key, with the certificate. Names without a rotated record answer as before.
    await set({ rail: 'at', mode: 'rotated' });
    const rotated = await verifyNameRecord((await resolve('at')).json(), { app: 'localpad', publisher: 'lukeinth', rail: 'at' });
    assert.equal(rotated.key, demos.find('localpad', 'successor').id);
    assert.equal(rotated.certificates.length, 1);
    assert.deepEqual([...rotated.publisherKey], [...before.publisherKey]);
    const untouched = await resolve('at', 'peersync');
    assert.equal(untouched.headers['x-rail-mode'], 'normal');

    await set({ rail: 'at', mode: 'normal' });
    assert.deepEqual(servers.rails, honest);
  });

  test('the legacy host serves the attack page with no policy at all, as the control', async () => {
    const host = 'legacy.localhost';
    const page = await request(net, { host, path: '/' });
    assert.equal(page.status, 200);
    assert.equal(page.headers['content-security-policy'], undefined);
    assert.match(page.text, /<title>LeakyTracker<\/title>/);
    for (const path of ['/app.js', '/app.css', '/base.css', '/keyweb-client.js', '/cover.png']) assert.equal((await request(net, { host, path })).status, 200, path);
    assert.equal((await request(net, { host, path: '/../localpad/app.js' })).status, 404);
  });
});

describe('starting and stopping', () => {
  test('a second pair of servers runs beside the first and closes without leaving a socket', async () => {
    const second = await startServers({ appPort: 0, mirrorPort: 0, bundlesDir: demos.dir });
    assert.notEqual(second.appPort, app);
    assert.match(second.appUrl, new RegExp(`^http://localhost:${second.appPort}/\\?mirror=${second.mirrorPort}$`));
    assert.equal((await request(second.appPort, { path: '/' })).status, 200);
    await second.close();
    assert.equal(await portOpen(second.appPort), false);
    assert.equal(await portOpen(second.mirrorPort), false);
    await second.close();
  });

  test('without built bundles the mirror has nothing, and says so', async () => {
    const empty = await startServers({ appPort: 0, mirrorPort: 0, bundlesDir: `${demos.dir}-missing` });
    try {
      assert.equal((await request(empty.mirrorPort, { path: `/mirrors/${pad.file}` })).status, 404);
      assert.equal((await request(empty.mirrorPort, { host: 'peer-1.localhost', path: `/swarm/announce/${pad.id}` })).status, 404);
      assert.equal((await request(empty.appPort, { path: '/demo-bundles/catalog.json' })).status, 404);
      assert.equal((await request(empty.appPort, { path: '/' })).status, 200);
    } finally {
      await empty.close();
    }
  });
});
