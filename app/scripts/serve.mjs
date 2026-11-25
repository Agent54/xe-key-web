#!/usr/bin/env node
// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Two loopback servers, no dependencies.
//
//   the browser   http://localhost:5760          the KeyWeb Runner page, under a strict policy
//                 http://<id>.localhost:5760     one real browser origin per signing key. The
//                                                server only ever hands these the loader; the
//                                                app itself is served by a service worker out
//                                                of the bundle the loader verified.
//
//   the network   http://localhost:5761          HTTP mirror of the signed demo bundles
//                 http://peer-N.localhost:5761   four swarm peers serving hashed chunks
//                 http://rail-at.localhost:5761  two resolver rails that turn a readable name into
//                 http://rail-dht.localhost:5761 a signed "this name is this key" record
//                 http://relay.localhost:5761    the sync relay (reached only through a capability)
//                 http://tracker.localhost:5761  the adversary's collection endpoint, with a ledger
//                                                (it also listens on UDP 5761, to catch WebRTC)
//                 http://legacy.localhost:5761   the attack page with no sandbox, as a control
//
// "Kill all servers" closes every listening socket on the network port for
// real. The browser port stays up: it stands in for the browser itself.
//
//   node scripts/serve.mjs
//   node scripts/serve.mjs --app-port N --mirror-port M
//
// Both listen on loopback only and refuse any Host that is not one of the
// names above.

import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_RELAY_BYTES } from '../runner/src/config.js';
import { NETWORK_RAILS } from '../runner/src/engine/names.js';
import { WORKER_CSP, loaderCsp, runnerCsp } from '../runner/src/engine/policy.js';
import { isKeyId } from '../runner/src/engine/swbn.js';
import { encodePng } from './lib/png.mjs';
import { APP_PORT, DEMOS_DIR, DEMO_BUNDLES_DIR, ENGINE_DIR, LOADER_DIR, MIRROR_PORT, PEER_COUNT, RUNNER_DIR, SHARED_DIR, SHARED_FILES, mimeFor } from './lib/site.mjs';

const TEXT = 'text/plain; charset=utf-8';
const JSON_TYPE = 'application/json; charset=utf-8';
const MAX_REPORT_BYTES = 16 * 1024;
const MAX_COLLECT_BYTES = 64 * 1024;
const TELEMETRY_KEPT = 200;
const BARE_AFTER_MS = 500;
/** What a resolver rail can be made to answer: the truth, a hijacker's record, or the record after a key rotation. */
const RAIL_MODES = Object.freeze(['normal', 'hijacked', 'rotated']);
const PIXEL = encodePng(1, 1, Buffer.from([0, 0, 0, 0]));
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const BASE_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
});

function hostName(request) {
  return String(request.headers.host || '').toLowerCase().replace(/:\d+$/, '');
}

function send(response, status, headers, body = '') {
  const bytes = typeof body === 'string' ? Buffer.from(body) : body;
  response.writeHead(status, { ...headers, 'Content-Length': bytes.length });
  response.end(bytes);
}

const sendJson = (response, status, headers, value) => send(response, status, { ...headers, 'Content-Type': JSON_TYPE }, JSON.stringify(value));

/** Reads a request body up to `limit` bytes. Resolves with a Buffer, or null if it was larger. */
function readBody(request, limit) {
  return new Promise((done) => {
    const parts = [];
    let size = 0;
    let over = false;
    request.on('data', (part) => {
      size += part.length;
      if (size > limit) over = true;
      else parts.push(part);
    });
    request.on('end', () => done(over ? null : Buffer.concat(parts)));
    request.on('error', () => done(null));
  });
}

/** Serves one file from `root`, or answers 404. Paths cannot leave the root. */
function serveFile(root, urlPath, request, response, headers) {
  let rel;
  try {
    rel = decodeURIComponent(urlPath);
  } catch {
    return send(response, 400, { ...headers, 'Content-Type': TEXT }, 'bad path');
  }
  if (rel.includes('\0') || rel.includes('\\')) return send(response, 400, { ...headers, 'Content-Type': TEXT }, 'bad path');
  if (rel.endsWith('/')) rel += 'index.html';
  const file = normalize(join(root, rel));
  const inside = file === root || file.startsWith(root + sep);
  const hidden = rel.split('/').some((part) => part.startsWith('.') && part !== '.well-known');
  let stat = null;
  if (inside && !hidden) {
    try { stat = statSync(file); } catch { stat = null; }
  }
  if (!stat || !stat.isFile()) return send(response, 404, { ...headers, 'Content-Type': TEXT }, 'not found');
  response.writeHead(200, { ...headers, 'Content-Type': mimeFor(file), 'Content-Length': stat.size });
  if (request.method === 'HEAD') return response.end();
  return createReadStream(file).pipe(response);
}

// ---------------------------------------------------------------- the demo bundles

/**
 * The built demo bundles, read once and again whenever the catalog file
 * changes: the catalog, each file's bytes, each key's chunk manifest, and
 * where every chunk lives.
 */
function bundleStore(dir) {
  let loadedAt = -1;
  let store = null;
  return () => {
    const catalogFile = join(dir, 'catalog.json');
    let mtime;
    try {
      mtime = statSync(catalogFile).mtimeMs;
    } catch {
      return null;
    }
    if (store && mtime === loadedAt) return store;
    const catalog = JSON.parse(readFileSync(catalogFile, 'utf8'));
    const files = new Map();
    const manifests = new Map();
    const chunks = new Map();
    for (const app of catalog.apps) {
      const bytes = readFileSync(join(dir, app.file));
      files.set(app.file, bytes);
      manifests.set(app.id, app.manifest);
      app.manifest.chunks.forEach((hash, index) => {
        const start = index * app.manifest.chunkSize;
        chunks.set(hash, bytes.subarray(start, Math.min(bytes.length, start + app.manifest.chunkSize)));
      });
    }
    loadedAt = mtime;
    store = { catalog, files, manifests, chunks };
    return store;
  };
}

// ---------------------------------------------------------------- the browser port

function appHandler(ctx) {
  const { ports } = ctx;
  const runnerOrigin = () => `http://localhost:${ports.app}`;

  const runnerHeaders = () => ({
    ...BASE_HEADERS,
    'Content-Security-Policy': runnerCsp({ appPort: ports.app, mirrorPort: ports.mirror }),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  });

  const api = async (url, request, response, headers) => {
    const path = url.pathname;
    if (path === '/api/network' && request.method === 'GET') {
      return sendJson(response, 200, headers, { up: ctx.network.up, mirrorPort: ports.mirror, control: true });
    }
    if ((path === '/api/network/kill' || path === '/api/network/revive') && request.method === 'POST') {
      // Only the runner page itself may pull the plug: its own Origin, plus a
      // header no cross-site form or simple request can send.
      if (request.headers.origin !== runnerOrigin() || request.headers['x-keyweb-control'] !== '1') {
        return sendJson(response, 403, headers, { error: 'FORBIDDEN' });
      }
      await readBody(request, 1024);
      try {
        if (path.endsWith('/kill')) await ctx.network.kill();
        else await ctx.network.revive();
      } catch (error) {
        return sendJson(response, 500, headers, { error: 'NETWORK_CONTROL_FAILED', detail: error.message });
      }
      return sendJson(response, 200, headers, { up: ctx.network.up, mirrorPort: ports.mirror, control: true });
    }
    if (path === '/api/rails' && request.method === 'GET') {
      return sendJson(response, 200, headers, { rails: ctx.rails, control: true });
    }
    if (path === '/api/rails' && request.method === 'POST') {
      // Switches what one resolver rail does: up or down, honest or not.
      if (request.headers.origin !== runnerOrigin() || request.headers['x-keyweb-control'] !== '1') {
        return sendJson(response, 403, headers, { error: 'FORBIDDEN' });
      }
      let wish = null;
      try {
        wish = JSON.parse((await readBody(request, 1024)).toString('utf8'));
      } catch {
        wish = null;
      }
      const state = wish && typeof wish.rail === 'string' && Object.hasOwn(ctx.rails, wish.rail) ? ctx.rails[wish.rail] : null;
      if (!state) return sendJson(response, 400, headers, { error: 'UNKNOWN_RAIL' });
      if (wish.mode !== undefined && !RAIL_MODES.includes(wish.mode)) return sendJson(response, 400, headers, { error: 'UNKNOWN_MODE' });
      if (typeof wish.down === 'boolean') state.down = wish.down;
      if (wish.mode !== undefined) state.mode = wish.mode;
      return sendJson(response, 200, headers, { rails: ctx.rails, control: true });
    }
    if (path === '/api/csp-report' && request.method === 'POST') {
      // Sent by the browser itself when a key origin's policy blocks
      // something. The app cannot stop it or see it.
      const body = await readBody(request, MAX_REPORT_BYTES);
      const id = url.searchParams.get('o');
      let report = null;
      try {
        report = body ? JSON.parse(body.toString('utf8'))['csp-report'] : null;
      } catch {
        report = null;
      }
      if (report && typeof report === 'object' && isKeyId(id)) {
        const text = (value) => (typeof value === 'string' ? value.slice(0, 300) : '');
        ctx.telemetry.push({
          seq: ++ctx.telemetrySeq,
          at: Date.now(),
          id,
          directive: text(report['effective-directive'] || report['violated-directive']).split(' ')[0],
          blocked: text(report['blocked-uri']),
          document: text(report['document-uri']),
        });
        if (ctx.telemetry.length > TELEMETRY_KEPT) ctx.telemetry.splice(0, ctx.telemetry.length - TELEMETRY_KEPT);
      }
      response.writeHead(204, BASE_HEADERS);
      return response.end();
    }
    if (path === '/api/telemetry' && request.method === 'GET') {
      const since = Number(url.searchParams.get('since')) || 0;
      return sendJson(response, 200, headers, { seq: ctx.telemetrySeq, events: ctx.telemetry.filter((event) => event.seq > since) });
    }
    return sendJson(response, 404, headers, { error: 'NOT_FOUND' });
  };

  const keyOrigin = (url, request, response) => {
    const headers = {
      ...BASE_HEADERS,
      'Content-Security-Policy': loaderCsp({ runnerOrigin: runnerOrigin() }),
      'Cross-Origin-Resource-Policy': 'same-origin',
    };
    if (request.method !== 'GET' && request.method !== 'HEAD') return send(response, 405, { ...headers, Allow: 'GET, HEAD', 'Content-Type': TEXT }, 'method not allowed');
    const path = url.pathname;
    if (path === '/__keyweb/sw.js') {
      return serveFile(LOADER_DIR, '/sw.js', request, response, { ...headers, 'Content-Security-Policy': WORKER_CSP, 'Service-Worker-Allowed': '/' });
    }
    const loaderFile = /^\/__keyweb\/(loader\.(?:html|js|css))$/.exec(path);
    if (loaderFile) return serveFile(LOADER_DIR, `/${loaderFile[1]}`, request, response, headers);
    const engineFile = /^\/__keyweb\/engine\/([a-z0-9-]+\.js)$/.exec(path);
    if (engineFile) return serveFile(ENGINE_DIR, `/${engineFile[1]}`, request, response, headers);
    // Everything else on a key origin comes from its verified bundle, by way
    // of the service worker. If a request reaches this server, there is none.
    return send(response, 404, { ...headers, 'Content-Type': TEXT }, 'no verified bundle is installed for this key origin: open it in KeyWeb Runner');
  };

  return (request, response) => {
    const name = hostName(request);
    const url = new URL(request.url, 'http://localhost');
    if (name === 'localhost') {
      const headers = runnerHeaders();
      if (url.pathname.startsWith('/api/')) {
        return api(url, request, response, headers).catch(() => {
          if (!response.headersSent) send(response, 500, { ...headers, 'Content-Type': TEXT }, 'internal error');
        });
      }
      if (request.method !== 'GET' && request.method !== 'HEAD') return send(response, 405, { ...headers, Allow: 'GET, HEAD', 'Content-Type': TEXT }, 'method not allowed');
      if (url.pathname.startsWith('/demo-bundles/')) return serveFile(ctx.bundlesDir, url.pathname.slice('/demo-bundles'.length), request, response, headers);
      return serveFile(RUNNER_DIR, url.pathname, request, response, headers);
    }
    const key = /^([a-z2-7]{56})\.localhost$/.exec(name);
    if (key && isKeyId(key[1])) return keyOrigin(url, request, response);
    return send(response, 421, { ...BASE_HEADERS, 'Content-Type': TEXT }, 'this server only answers to localhost and to key origins');
  };
}

// ---------------------------------------------------------------- the network port

function mirrorHandler(ctx) {
  const { ports } = ctx;
  const runnerOrigin = () => `http://localhost:${ports.app}`;
  const open = { ...BASE_HEADERS, 'Access-Control-Allow-Origin': '*', 'Cross-Origin-Resource-Policy': 'cross-origin' };
  const runnerOnly = () => ({ ...BASE_HEADERS, 'Access-Control-Allow-Origin': runnerOrigin(), Vary: 'Origin' });
  const getOnly = (request, response, headers) => {
    if (request.method === 'GET' || request.method === 'HEAD') return false;
    send(response, 405, { ...headers, Allow: 'GET, HEAD', 'Content-Type': TEXT }, 'method not allowed');
    return true;
  };

  const mirror = (url, request, response) => {
    if (getOnly(request, response, open)) return undefined;
    const store = ctx.bundles();
    const match = /^\/mirrors\/([a-z0-9][a-z0-9.-]{0,80}\.swbn)$/.exec(url.pathname);
    const bytes = match && store ? store.files.get(match[1]) : null;
    if (!bytes) return send(response, 404, { ...open, 'Content-Type': TEXT }, 'not on this mirror');
    return send(response, 200, { ...open, 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${match[1]}"` }, request.method === 'HEAD' ? '' : bytes);
  };

  const peer = (number, url, request, response) => {
    if (getOnly(request, response, open)) return undefined;
    const store = ctx.bundles();
    const announce = /^\/swarm\/announce\/([a-z2-7]{56})$/.exec(url.pathname);
    if (announce) {
      const manifest = store ? store.manifests.get(announce[1]) : null;
      if (!manifest) return sendJson(response, 404, open, { error: 'UNKNOWN_KEY' });
      return sendJson(response, 200, open, manifest);
    }
    const wanted = /^\/swarm\/chunk\/([0-9a-f]{64})$/.exec(url.pathname);
    const chunk = wanted && store ? store.chunks.get(wanted[1]) : null;
    if (!chunk) return send(response, 404, { ...open, 'Content-Type': TEXT }, 'this peer does not have that chunk');
    let body = chunk;
    if (url.searchParams.get('poison') === '1') {
      // A malicious peer: right length, right name, wrong bytes.
      body = Buffer.from(chunk);
      body[0] ^= 0xff;
      body[body.length >> 1] ^= 0x5a;
    }
    // Peers are not equally fast.
    const timer = setTimeout(() => send(response, 200, { ...open, 'Content-Type': 'application/octet-stream', 'X-Peer': `peer-${number}` }, body), 12 + number * 14);
    response.on('close', () => clearTimeout(timer));
    return undefined;
  };

  const relay = async (url, request, response) => {
    const headers = runnerOnly();
    if (request.method === 'OPTIONS') {
      response.writeHead(204, { ...headers, 'Access-Control-Allow-Methods': 'GET, PUT', 'Access-Control-Allow-Headers': 'content-type', 'Access-Control-Max-Age': '600' });
      return response.end();
    }
    const match = /^\/sync\/([a-z2-7]{56})$/.exec(url.pathname);
    if (!match || !isKeyId(match[1])) return sendJson(response, 404, headers, { error: 'NOT_FOUND' });
    if (request.method === 'GET') {
      const held = ctx.relay.get(match[1]);
      if (!held) return sendJson(response, 200, headers, { data: null, bytes: 0, version: 0, at: null });
      return sendJson(response, 200, headers, { data: held.data, bytes: Buffer.byteLength(held.data), version: held.version, at: held.at });
    }
    if (request.method === 'PUT') {
      const body = await readBody(request, MAX_RELAY_BYTES);
      if (body === null) return sendJson(response, 413, headers, { error: 'TOO_LARGE' });
      const version = (ctx.relay.get(match[1])?.version || 0) + 1;
      ctx.relay.set(match[1], { data: body.toString('utf8'), version, at: Date.now() });
      return sendJson(response, 200, headers, { ok: true, bytes: body.length, version });
    }
    return send(response, 405, { ...headers, Allow: 'GET, PUT, OPTIONS', 'Content-Type': TEXT }, 'method not allowed');
  };

  const tracker = async (url, request, response) => {
    if (url.pathname === '/stats' && request.method === 'GET') {
      return sendJson(response, 200, runnerOnly(), {
        requests: ctx.ledger.requests, bytes: ctx.ledger.bytes, datagrams: ctx.ledger.datagrams, connections: ctx.ledger.connections, recent: ctx.ledger.recent,
      });
    }
    if (url.pathname !== '/collect') return send(response, 404, { ...open, 'Content-Type': TEXT }, 'not found');
    const body = request.method === 'GET' || request.method === 'HEAD' ? Buffer.alloc(0) : await readBody(request, MAX_COLLECT_BYTES);
    ctx.ledger.record(request.method, url, body ? body.length : MAX_COLLECT_BYTES);
    if (request.method === 'GET' || request.method === 'HEAD') return send(response, 200, { ...open, 'Content-Type': 'image/png' }, PIXEL);
    return send(response, 200, { ...open, 'Content-Type': TEXT }, 'collected');
  };

  // A resolver rail: answers "which key is this name?" with a signed
  // record. It can be down, and it can lie; what it says in each mode was
  // signed at build time, so a lie is a real record under the wrong key.
  const rail = (name, url, request, response) => {
    const state = ctx.rails[name];
    // Down means down: the connection is dropped without an answer.
    if (state.down) return request.socket.destroy();
    if (getOnly(request, response, open)) return undefined;
    const match = /^\/resolve\/([a-z0-9][a-z0-9-]{0,31})\/([a-z0-9][a-z0-9-]{0,31})$/.exec(url.pathname);
    if (match) {
      for (const mode of [state.mode, 'normal']) {
        let bytes = null;
        try {
          bytes = readFileSync(join(ctx.bundlesDir, 'names', mode, name, match[1], `${match[2]}.json`));
        } catch {
          bytes = null;
        }
        if (bytes) return send(response, 200, { ...open, 'Content-Type': JSON_TYPE, 'X-Rail-Mode': mode }, request.method === 'HEAD' ? '' : bytes);
      }
    }
    return sendJson(response, 404, open, { error: 'NO_SUCH_NAME' });
  };

  const legacy = (url, request, response) => {
    // On purpose: no policy at all. This is the web the sandbox is compared with.
    if (getOnly(request, response, BASE_HEADERS)) return undefined;
    const root = SHARED_FILES.includes(url.pathname.slice(1)) ? SHARED_DIR : join(DEMOS_DIR, 'leakytracker');
    return serveFile(root, url.pathname, request, response, BASE_HEADERS);
  };

  const route = (request) => {
    const name = hostName(request);
    if (name === 'localhost') return ['mirror'];
    if (name === 'relay.localhost') return ['relay'];
    if (name === 'tracker.localhost') return ['tracker'];
    if (name === 'legacy.localhost') return ['legacy'];
    const resolver = /^rail-([a-z]+)\.localhost$/.exec(name);
    if (resolver && Object.hasOwn(ctx.rails, resolver[1])) return ['rail', resolver[1]];
    const match = /^peer-([1-9])\.localhost$/.exec(name);
    if (match && Number(match[1]) <= PEER_COUNT) return ['peer', Number(match[1])];
    return null;
  };

  const onRequest = (request, response) => {
    const target = route(request);
    if (!target) return send(response, 421, { ...BASE_HEADERS, 'Content-Type': TEXT }, 'no such host on this network');
    const url = new URL(request.url, 'http://localhost');
    const fail = () => {
      if (!response.headersSent) send(response, 500, { ...BASE_HEADERS, 'Content-Type': TEXT }, 'internal error');
    };
    if (target[0] === 'mirror') return mirror(url, request, response);
    if (target[0] === 'peer') return peer(target[1], url, request, response);
    if (target[0] === 'relay') return relay(url, request, response).catch(fail);
    if (target[0] === 'tracker') return tracker(url, request, response).catch(fail);
    if (target[0] === 'rail') return rail(target[1], url, request, response);
    return legacy(url, request, response);
  };

  // The tracker also accepts WebSockets, so that an unblocked connection really opens.
  const onUpgrade = (request, socket) => {
    const target = route(request);
    const url = new URL(request.url, 'http://localhost');
    const key = request.headers['sec-websocket-key'];
    if (!target || target[0] !== 'tracker' || url.pathname !== '/ws' || typeof key !== 'string') return socket.destroy();
    ctx.ledger.record('WEBSOCKET', url, 0);
    const accept = createHash('sha1').update(key + WS_GUID).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    // Say goodbye, then hang up: this endpoint only exists to be reached.
    const timer = setTimeout(() => {
      socket.end(Buffer.from([0x88, 0x00]));
      setTimeout(() => socket.destroy(), 250).unref();
    }, 150);
    socket.resume();
    socket.on('close', () => clearTimeout(timer));
    socket.on('error', () => socket.destroy());
    return undefined;
  };

  return { onRequest, onUpgrade };
}

/**
 * What the tracker has actually received: the only honest measure of a leak.
 *
 *   requests, bytes   everything that carried data: HTTP requests, WebSocket
 *                     handshakes and UDP datagrams
 *   datagrams         the UDP part of that (WebRTC sends STUN over UDP)
 *   connections       TCP connections that were opened and never said
 *                     anything, which is what a preconnect looks like
 */
function makeLedger() {
  return {
    requests: 0,
    bytes: 0,
    datagrams: 0,
    connections: 0,
    recent: [],
    add(method, via, bytes) {
      this.requests += 1;
      this.bytes += bytes;
      this.recent.push({ method, via: String(via || '').slice(0, 24), bytes, at: Date.now() });
      if (this.recent.length > 20) this.recent.shift();
    },
    record(method, url, bodyBytes) {
      this.add(method, url.searchParams.get('via'), Math.max(0, Buffer.byteLength(url.search) - 1) + bodyBytes);
    },
    datagram(bytes) {
      this.datagrams += 1;
      this.add('UDP', 'datagram', bytes);
    },
    bareConnection() {
      this.connections += 1;
    },
  };
}

// ---------------------------------------------------------------- listening

/** Listens on IPv4 loopback, and on IPv6 loopback too where the machine has it. */
async function listenLoopback(onRequest, port, { onUpgrade = null, onBareConnection = null } = {}) {
  // Every socket is tracked, so closing really closes: an upgraded
  // (WebSocket) connection is no longer the HTTP server's to end.
  const sockets = new Set();
  const spoke = new WeakSet();
  const listen = (host, onPort) => new Promise((done, fail) => {
    const server = createServer((request, response) => {
      spoke.add(request.socket);
      onRequest(request, response);
    });
    server.on('connection', (socket) => {
      sockets.add(socket);
      // A client with something to say says it at once. A connection that
      // is still silent after a moment, or closes without a word, is a bare
      // one: that is what a preconnect looks like from this side.
      let counted = false;
      const bare = () => {
        if (counted || !onBareConnection || spoke.has(socket)) return;
        counted = true;
        onBareConnection();
      };
      const timer = setTimeout(bare, BARE_AFTER_MS);
      socket.on('close', () => {
        clearTimeout(timer);
        sockets.delete(socket);
        bare();
      });
    });
    server.on('upgrade', (request, socket) => {
      spoke.add(socket);
      if (onUpgrade) onUpgrade(request, socket);
      else socket.destroy();
    });
    server.once('error', fail);
    server.listen(onPort, host, () => {
      server.removeListener('error', fail);
      done(server);
    });
  });
  const v4 = await listen('127.0.0.1', port);
  const actual = v4.address().port;
  const servers = [v4];
  try {
    servers.push(await listen('::1', actual));
  } catch {
    // No IPv6 loopback, or the port is taken there: IPv4 is enough.
  }
  const close = () => Promise.all(servers.map((server) => new Promise((done) => {
    server.close(() => done());
    server.closeAllConnections();
    for (const socket of sockets) socket.destroy();
  })));
  return { port: actual, close };
}

/**
 * The tracker's UDP side, on the same port number. WebRTC is the one way a
 * page can make the browser send UDP, so anything that arrives here came
 * past every policy a page can set. Resolves with a close function, or
 * null if the port is not free for UDP.
 */
function listenDatagrams(port, onDatagram) {
  return new Promise((done) => {
    const socket = createSocket('udp4');
    socket.once('error', () => {
      socket.close();
      done(null);
    });
    socket.on('message', (message) => onDatagram(message.length));
    socket.bind(port, '127.0.0.1', () => {
      socket.removeAllListeners('error');
      socket.on('error', () => {});
      done(() => new Promise((closed) => socket.close(closed)));
    });
  });
}

/**
 * Starts both servers. Port 0 picks a free port. Resolves with
 * {appPort, mirrorPort, appUrl, networkUp(), kill(), revive(), ledger, close()}.
 */
export async function startServers({ appPort = APP_PORT, mirrorPort = MIRROR_PORT, bundlesDir = DEMO_BUNDLES_DIR } = {}) {
  const ctx = {
    ports: { app: appPort, mirror: mirrorPort },
    bundlesDir: resolve(bundlesDir),
    bundles: bundleStore(resolve(bundlesDir)),
    telemetry: [],
    telemetrySeq: 0,
    relay: new Map(),
    rails: Object.fromEntries(NETWORK_RAILS.map((rail) => [rail, { down: false, mode: 'normal' }])),
    ledger: makeLedger(),
    network: { up: false, close: null, kill: null, revive: null },
  };
  const handlers = mirrorHandler(ctx);
  ctx.network.revive = async () => {
    if (ctx.network.up) return;
    const listening = await listenLoopback(handlers.onRequest, ctx.ports.mirror, {
      onUpgrade: handlers.onUpgrade,
      onBareConnection: () => ctx.ledger.bareConnection(),
    });
    ctx.ports.mirror = listening.port;
    const closeDatagrams = await listenDatagrams(listening.port, (bytes) => ctx.ledger.datagram(bytes));
    ctx.network.close = async () => {
      if (closeDatagrams) await closeDatagrams();
      await listening.close();
    };
    ctx.network.up = true;
  };
  ctx.network.kill = async () => {
    if (!ctx.network.up) return;
    ctx.network.up = false;
    const close = ctx.network.close;
    ctx.network.close = null;
    await close();
  };

  await ctx.network.revive();
  let app;
  try {
    app = await listenLoopback(appHandler(ctx), appPort);
  } catch (error) {
    await ctx.network.kill();
    throw error;
  }
  ctx.ports.app = app.port;
  const query = ctx.ports.mirror === MIRROR_PORT ? '' : `?mirror=${ctx.ports.mirror}`;
  return {
    appPort: ctx.ports.app,
    mirrorPort: ctx.ports.mirror,
    appUrl: `http://localhost:${ctx.ports.app}/${query}`,
    networkUp: () => ctx.network.up,
    kill: ctx.network.kill,
    revive: ctx.network.revive,
    ledger: ctx.ledger,
    rails: ctx.rails,
    close: async () => {
      await ctx.network.kill();
      await app.close();
    },
  };
}

async function main(argv) {
  const port = (name, fallback) => {
    const index = argv.indexOf(name);
    if (index < 0) return fallback;
    const value = Number(argv[index + 1]);
    if (!Number.isInteger(value) || value < 0 || value > 65535) throw new Error(`${name} needs a port number`);
    return value;
  };
  if (!existsSync(join(DEMO_BUNDLES_DIR, 'catalog.json'))) {
    console.log('the signed demo bundles have not been built yet: building them now');
    const { buildAll } = await import('./build-swbn.mjs');
    await buildAll({ log: (line) => console.log(`  ${line}`) });
  }
  const running = await startServers({ appPort: port('--app-port', APP_PORT), mirrorPort: port('--mirror-port', MIRROR_PORT) });
  console.log(`runner   ${running.appUrl}`);
  console.log(`network  http://localhost:${running.mirrorPort}/  (mirror, ${PEER_COUNT} swarm peers, relay, tracker)`);
  console.log('loopback only. Ctrl+C to stop.');
  const stop = () => running.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`serve: ${error.message}`);
    process.exitCode = 1;
  });
}
