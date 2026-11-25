// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// KeyWeb Runner: a browser for key origins. A link names a signing key.
// The runner fetches bytes for it over whatever transport works, verifies
// them here in the page, and opens the app in a frame it cannot send
// anything out of. This file is the wiring between those parts.

import { CAPABILITIES, GrantBook, checkArguments } from './capabilities.js';
import { bundleCache, jsonStore } from './cache.js';
import { MAX_BUNDLE_BYTES, MIRROR_PORT } from './config.js';
import { byId, bytesText, el, fill } from './dom.js';
import { base64, base64Decode, base64url } from './engine/bytes.js';
import { RAILS, addressOfKey, parseAddress, publisherAnchor, verifyNameRecord } from './engine/names.js';
import { keyOriginUrl } from './engine/policy.js';
import { verifyRotation } from './engine/rotation.js';
import { FAILURE_TEXT, fingerprint, inspectSwbn, readDescriptor, shortId } from './engine/swbn.js';
import { PetnameBook, RotationBook, nameKey, petnameLabel } from './petnames.js';
import { PinBook, judgeRecord } from './pins.js';
import { adoptRotation, commitmentFor } from './rotate.js';
import { Sandbox } from './sandbox.js';
import { makeTransports } from './transports.js';
import { addLog, addTelemetry, createTrace, remaining, renderFacts, renderGrants, renderSteps, renderVerdict } from './ui-inspector.js';
import { initNames } from './ui-names.js';
import { renderTrust } from './ui-trust.js';

const TRANSPORT_LABEL = Object.freeze({ http: 'HTTP mirror', swarm: 'P2P swarm', cache: 'Offline cache', file: 'File drop', paste: 'Pasted base64' });

const params = new URLSearchParams(location.search);
const wantedPort = Number(params.get('mirror'));
const mirrorPort = Number.isInteger(wantedPort) && wantedPort > 0 && wantedPort < 65536 ? wantedPort : MIRROR_PORT;

const state = {
  catalog: { apps: [], names: [], rotation: null },
  api: false,
  networkUp: true,
  simulatedOutage: false,
  session: null,
  loaded: null,
  opening: 0,
  booted: 0,
  telemetrySeq: 0,
  grantQueue: [],
  ledger: null,
};

const cache = bundleCache();
const petnames = new PetnameBook(jsonStore('keyweb.petnames', []));
const rotations = new RotationBook(jsonStore('keyweb.rotations', {}));
const pins = new PinBook(jsonStore('keyweb.pins', {}));
const grants = new GrantBook();
let namesPanel = { refresh: async () => {} };
const trustNodes = { pill: byId('trust-pill'), panel: byId('trust-panel'), summary: byId('trust-summary'), facts: byId('trust-facts') };
const transports = makeTransports({ mirrorPort, cache, net: { simulatedOutage: () => state.simulatedOutage } });
const trace = createTrace(byId('trace'), byId('swarm'), byId('swarm-grid'));

const viewport = byId('viewport');
const keyOrigin = (id) => keyOriginUrl(id, { protocol: location.protocol, port: location.port });
const catalogEntry = (id) => state.catalog.apps.find((app) => app.id === id) || null;

/** A file from the runner's own origin: the demo bundles ship inside it. */
async function fetchSelf(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return response;
}

/** A demo bundle for a key, from the runner's own files, or null. Whoever asks verifies it. */
async function fetchBundle(id) {
  const entry = catalogEntry(id);
  if (!entry) return null;
  try {
    return new Uint8Array(await (await fetchSelf(`demo-bundles/${entry.file}`)).arrayBuffer());
  } catch {
    return null;
  }
}

/** Puts text on the clipboard. Resolves true if it got there. */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // No clipboard permission: fall back to a selection and the copy command.
    const field = el('textarea', { class: 'visually-hidden', readonly: true });
    field.value = text;
    document.body.append(field);
    field.select();
    let done = false;
    try {
      done = document.execCommand('copy');
    } catch {
      done = false;
    }
    field.remove();
    return done;
  }
}

/** Copies a link and says so on the button that was pressed. */
async function copyLink(button, text) {
  const copied = await copyText(text);
  const label = button.dataset.label || button.textContent;
  button.dataset.label = label;
  button.dataset.copied = copied ? text : '';
  button.textContent = copied ? 'Copied' : 'Copy failed';
  setTimeout(() => {
    button.textContent = label;
  }, 1400);
}

// ---------------------------------------------------------------- views

function showTab(name) {
  for (const tab of ['browse', 'names']) {
    byId(`tab-${tab}`).setAttribute('aria-selected', String(tab === name));
    byId(`view-${tab}`).hidden = tab !== name;
  }
}

function showNotice(kind, text) {
  const notice = byId('notice');
  notice.hidden = !text;
  notice.className = `notice notice-${kind}`;
  notice.textContent = text || '';
}

function showStage(which) {
  byId('start').hidden = which !== 'start';
  byId('blocked').hidden = which !== 'blocked';
}

function showBlocked(code, text) {
  byId('blocked-code').textContent = code;
  byId('blocked-text').textContent = text;
  showStage('blocked');
}

// ---------------------------------------------------------------- the network switch

async function readNetwork() {
  try {
    const answer = await (await fetch('api/network', { cache: 'no-store' })).json();
    state.api = answer.control === true;
    state.networkUp = answer.up === true;
  } catch {
    // No control API: this is the installed app, or a plain static host.
    state.api = false;
    state.networkUp = !state.simulatedOutage;
  }
  renderNetwork();
}

function renderNetwork() {
  const up = state.api ? state.networkUp : !state.simulatedOutage;
  const pill = byId('net-pill');
  pill.className = `net-pill ${up ? 'net-up' : 'net-down'}`;
  if (up) pill.textContent = `Network up: mirror, 4 peers, relay and tracker on :${mirrorPort}`;
  else pill.textContent = state.api ? `ALL SERVERS KILLED: every socket on :${mirrorPort} is closed` : 'Network switched off (simulated: there is no dev server to kill)';
  const button = byId('net-toggle');
  button.textContent = up ? 'Kill all servers' : 'Revive the servers';
  button.className = up ? 'btn btn-danger' : 'btn btn-primary';
  button.title = up ? 'Simulate censorship or an outage: close the mirror, the swarm peers, the relay and the tracker' : 'Bring the network back';
}

async function toggleNetwork() {
  const button = byId('net-toggle');
  button.disabled = true;
  try {
    if (state.api) {
      const action = state.networkUp ? 'kill' : 'revive';
      const response = await fetch(`api/network/${action}`, { method: 'POST', headers: { 'X-KeyWeb-Control': '1' } });
      const answer = await response.json();
      if (!response.ok) throw new Error(answer.detail || answer.error || 'the control request was refused');
      state.networkUp = answer.up === true;
    } else {
      state.simulatedOutage = !state.simulatedOutage;
    }
  } catch (error) {
    showNotice('bad', `Could not switch the network: ${error.message}`);
  }
  button.disabled = false;
  renderNetwork();
  await refreshLedger();
}

// ---------------------------------------------------------------- the tracker's ledger and the browser's reports

async function readLedger() {
  if (state.simulatedOutage) return null;
  try {
    const response = await fetch(`http://tracker.localhost:${mirrorPort}/stats`, { cache: 'no-store', credentials: 'omit' });
    if (!response.ok) return null;
    const answer = await response.json();
    return { requests: Number(answer.requests) || 0, bytes: Number(answer.bytes) || 0, datagrams: Number(answer.datagrams) || 0, connections: Number(answer.connections) || 0 };
  } catch {
    return null;
  }
}

async function refreshLedger() {
  state.ledger = await readLedger();
  const node = byId('status-ledger');
  const session = state.session;
  if (!state.ledger) {
    node.className = 'status-item status-ledger ledger-unknown';
    node.textContent = 'Tracker ledger: the tracker is unreachable, so it received nothing';
    return;
  }
  if (session && session.ledgerBase) {
    const requests = state.ledger.requests - session.ledgerBase.requests;
    const leaked = state.ledger.bytes - session.ledgerBase.bytes;
    const bare = state.ledger.connections - session.ledgerBase.connections;
    // A bare connection carries no data, but the tracker can see that it
    // happened, so it is never reported as nothing.
    node.className = `status-item status-ledger ${requests > 0 ? 'ledger-leak' : bare > 0 ? 'ledger-warn' : 'ledger-clean'}`;
    node.dataset.requests = String(requests);
    node.dataset.bare = String(bare);
    node.textContent = `Tracker ledger since this app opened: ${requests} request${requests === 1 ? '' : 's'}, ${leaked} byte${leaked === 1 ? '' : 's'} leaked`
      + (bare > 0 ? `; ${bare} bare connection${bare === 1 ? '' : 's'} with no data (known gap: the browser connects before it checks)` : '');
  } else {
    node.className = 'status-item status-ledger';
    node.textContent = `Tracker ledger: ${state.ledger.requests} request${state.ledger.requests === 1 ? '' : 's'}, ${state.ledger.bytes} bytes received in total`;
  }
}

async function pollTelemetry() {
  if (!state.api) return;
  try {
    const answer = await (await fetch(`api/telemetry?since=${state.telemetrySeq}`, { cache: 'no-store' })).json();
    state.telemetrySeq = answer.seq;
    for (const event of answer.events) {
      if (state.session && event.id === state.session.id) addTelemetry(byId('telemetry'), { ...event, source: 'browser' });
    }
  } catch {
    // The runner's own server went away; nothing to show.
  }
}

// ---------------------------------------------------------------- chrome around the frame

function renderChrome() {
  const session = state.session;
  const tier = byId('tier');
  const chip = byId('name-chip');
  byId('reload').disabled = !state.loaded || !state.loaded.report.ok;
  byId('close').disabled = !session;
  byId('copy-link').disabled = !session;
  byId('tamper').disabled = !state.loaded || !state.loaded.originalOk;
  renderTrust(trustNodes, session ? session.trust : null);
  if (!session) {
    delete document.documentElement.dataset.running;
    tier.className = 'tier tier-idle';
    tier.textContent = 'No app open';
    chip.hidden = true;
    byId('status-policy').textContent = 'Sandbox idle';
    renderGrants(byId('grants'), [], Date.now(), () => {});
    return;
  }
  const live = grants.list(session.id);
  if (live.length === 0) {
    tier.className = 'tier tier-0';
    tier.textContent = 'Tier 0: zero exfiltration';
  } else {
    tier.className = 'tier tier-1';
    tier.textContent = `Tier 1: ${live.map((grant) => `${grant.capability} ${grant.mode === 'once' ? '(once)' : remaining(grant.expires - Date.now())}`).join(', ')}`;
  }
  chip.hidden = false;
  if (session.judge.status === 'petname') {
    chip.className = 'name-chip chip-petname';
    chip.textContent = session.judge.name;
    chip.title = 'Your petname for this key';
  } else if (session.judge.status === 'impostor') {
    chip.className = 'name-chip chip-impostor';
    chip.textContent = `Not “${session.judge.name}”`;
    chip.title = 'This bundle claims a name you bound to a different key';
  } else {
    chip.className = 'name-chip chip-claim';
    chip.textContent = session.judge.name ? `claims “${session.judge.name}”` : 'unnamed key';
    chip.title = 'A name the bundle gives itself. You have not bound a petname to this key.';
  }
  byId('address').value = session.trust.address;
  byId('status-policy').textContent = "Sandbox: connect-src 'none', img-src 'self', form-action 'none', no popups, no top navigation";
  renderGrants(byId('grants'), live, Date.now(), (grant) => {
    grants.revoke(grant.id, grant.capability);
    addLog(byId('cap-log'), 'info', `${grant.capability}: revoked by you`);
    renderChrome();
  });
}

function closeSession() {
  const session = state.session;
  state.session = null;
  if (session) {
    session.sandbox.destroy();
    grants.revokeAll(session.id);
  }
  for (const pending of state.grantQueue.splice(0)) pending.settle({ ok: false, error: 'CLOSED' });
  byId('grant').hidden = true;
  renderChrome();
}

// ---------------------------------------------------------------- capability requests

function replyTo(session, rid, body) {
  if (state.session === session) session.sandbox.post({ type: 'cap.result', rid, ...body });
}

function nextGrantCard() {
  const card = byId('grant');
  const pending = state.grantQueue[0];
  if (!pending) {
    card.hidden = true;
    return;
  }
  const { session, capability, reason } = pending;
  const info = CAPABILITIES[capability];
  const who = session.judge.status === 'petname' ? `“${session.judge.name}” (your petname)` : session.judge.name ? `An app that calls itself “${session.judge.name}”` : 'An unnamed app';
  byId('grant-who').textContent = `${who} at ${shortId(session.id)} asks for one capability:`;
  fill(byId('grant-title'), el('span', { class: 'mono' }, capability), ` ${info.title}`);
  byId('grant-what').textContent = `If you grant it, the app can: ${info.grants}`;
  fill(byId('grant-limits'), info.limits.map((limit) => el('li', {}, limit)));
  byId('grant-reason').textContent = reason || '(no reason given)';
  card.hidden = false;
  byId('grant-deny').focus();
}

function decideGrant(mode) {
  const pending = state.grantQueue.shift();
  if (!pending) return;
  if (mode === null) {
    addLog(byId('cap-log'), 'bad', `${pending.capability}: denied by you`);
    pending.settle({ ok: false, error: 'DENIED' });
  } else {
    const grant = grants.grant(pending.session.id, pending.capability, mode);
    addLog(byId('cap-log'), 'ok', `${pending.capability}: granted ${mode === 'once' ? 'for one use' : 'for 5 minutes'}`);
    pending.settle({ ok: true, mode: grant.mode, expires: grant.expires });
  }
  renderChrome();
  nextGrantCard();
}

function onCapabilityRequest(session, message) {
  const capability = message.cap;
  const screened = grants.screen(capability, session.descriptor.capabilities);
  if (!screened.ok) {
    addLog(byId('cap-log'), 'bad', `${String(capability).slice(0, 48)}: refused without asking you (${screened.code})`);
    replyTo(session, message.rid, { ok: false, error: screened.code });
    return;
  }
  const live = grants.check(session.id, capability);
  if (live.ok) {
    replyTo(session, message.rid, { ok: true, mode: live.grant.mode, expires: live.grant.expires });
    return;
  }
  if (state.grantQueue.length >= 4) {
    replyTo(session, message.rid, { ok: false, error: 'TOO_MANY_REQUESTS' });
    return;
  }
  state.grantQueue.push({
    session,
    capability,
    reason: typeof message.reason === 'string' ? message.reason.replace(/\s+/g, ' ').slice(0, 200) : '',
    settle: (body) => replyTo(session, message.rid, body),
  });
  if (state.grantQueue.length === 1) nextGrantCard();
}

class OperationError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** Carries out one granted operation on the app's behalf. The app's own sandbox never opens. */
async function perform(session, capability, args) {
  if (capability === 'net:sync-relay') {
    if (state.simulatedOutage) throw new OperationError('RELAY_UNREACHABLE');
    const url = `http://relay.localhost:${mirrorPort}/sync/${session.id}`;
    let response;
    try {
      response = args.op === 'push'
        ? await fetch(url, { method: 'PUT', body: args.data, headers: { 'Content-Type': 'text/plain' }, credentials: 'omit', referrerPolicy: 'no-referrer' })
        : await fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    } catch {
      throw new OperationError('RELAY_UNREACHABLE');
    }
    if (!response.ok) throw new OperationError('RELAY_REFUSED');
    const answer = await response.json();
    if (args.op === 'push') return { op: 'push', bytes: answer.bytes, version: answer.version };
    return { op: 'pull', data: typeof answer.data === 'string' ? answer.data : null, version: answer.version };
  }
  if (capability === 'storage:export') {
    const url = URL.createObjectURL(new Blob([args.text], { type: 'text/plain' }));
    const link = el('a', { href: url, download: args.filename, class: 'visually-hidden' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    return { filename: args.filename, bytes: new TextEncoder().encode(args.text).length };
  }
  throw new OperationError('UNKNOWN_CAPABILITY');
}

async function onCapabilityInvoke(session, message) {
  const capability = message.cap;
  const fail = (code) => {
    addLog(byId('cap-log'), 'bad', `${String(capability).slice(0, 48)}: operation refused (${code})`);
    replyTo(session, message.rid, { ok: false, error: code });
  };
  if (typeof capability !== 'string' || !Object.hasOwn(CAPABILITIES, capability)) return fail('UNKNOWN_CAPABILITY');
  const args = checkArguments(capability, message.args);
  if (!args.ok) return fail(args.code);
  const used = grants.use(session.id, capability);
  renderChrome();
  if (!used.ok) return fail(used.code);
  try {
    const result = await perform(session, capability, args);
    const what = capability === 'net:sync-relay'
      ? (result.op === 'push' ? `pushed ${result.bytes} bytes to the relay` : `pulled ${result.data === null ? 'nothing (the relay holds no data)' : `${result.data.length} characters`} from the relay`)
      : `saved ${result.filename} (${result.bytes} bytes)`;
    addLog(byId('cap-log'), 'ok', `${capability}: ${what}`);
    replyTo(session, message.rid, { ok: true, result });
  } catch (error) {
    fail(error instanceof OperationError ? error.code : 'OPERATION_FAILED');
  }
  return undefined;
}

function onAppMessage(session, message) {
  if (state.session !== session) return;
  if (message.type === 'hello') {
    session.sandbox.post({
      type: 'context',
      context: {
        origin: session.report.origin,
        transport: session.transport,
        tier: 0,
        capabilities: session.descriptor.capabilities,
        lab: { tracker: `http://tracker.localhost:${mirrorPort}` },
      },
    });
  } else if (message.type === 'cap.request') onCapabilityRequest(session, message);
  else if (message.type === 'cap.invoke') onCapabilityInvoke(session, message);
  else if (message.type === 'telemetry') {
    // Without the dev server there are no browser reports to show, so the
    // app's own account is shown instead, and marked as such.
    if (!state.api && message.data && typeof message.data === 'object') {
      addTelemetry(byId('telemetry'), { at: Date.now(), directive: String(message.data.directive || '').slice(0, 40), blocked: String(message.data.blocked || '').slice(0, 200), source: 'app' });
    }
  } else if (message.type === 'attack.done') {
    setTimeout(() => {
      pollTelemetry();
      refreshLedger();
    }, 400);
  } else if (message.type === 'gap.done') {
    // The app probed the channels no page policy closes. Only the tracker
    // knows whether anything arrived, so ask it, and say so either way.
    setTimeout(async () => {
      if (state.session !== session) return;
      const now = await readLedger();
      await refreshLedger();
      if (state.session !== session) return;
      if (!now || !session.ledgerBase) {
        showNotice('bad', 'The gap probe ran, but the tracker is unreachable, so nothing can be confirmed either way.');
        return;
      }
      const datagrams = now.datagrams - session.ledgerBase.datagrams;
      const connections = now.connections - session.ledgerBase.connections;
      session.sandbox.post({ type: 'gap.ledger', datagrams, connections });
      if (datagrams + connections > 0) {
        showNotice('bad', `Known gap confirmed. Since this app opened, the tracker received ${datagrams} UDP datagram${datagrams === 1 ? '' : 's'} sent by WebRTC and ${connections} bare TCP connection${connections === 1 ? '' : 's'} opened by preconnect. No policy a web page can set stops either one: closing them takes the browser itself.`);
      } else {
        showNotice('ok', 'The tracker saw no UDP datagram and no bare connection: in this browser both known gaps are closed.');
      }
    }, 1800);
  }
}

// ---------------------------------------------------------------- verify and open

async function renderInspector(report, descriptor) {
  renderSteps(byId('steps'), report.steps);
  renderVerdict(byId('verdict'), report.ok
    ? { ok: true, code: 'VERIFIED', text: `Signed by the key behind ${shortId(report.id)}. That key is the origin.` }
    : { ok: false, code: report.code, text: `${FAILURE_TEXT[report.code] || 'verification failed'}.` });
  renderFacts(byId('facts'), byId('resources'), byId('resources-summary'), {
    report,
    descriptor,
    servedAt: report.ok ? keyOrigin(report.id) : '',
    fingerprint: report.ok ? await fingerprint(report.publicKey) : '',
  });
}

/**
 * Everything the trust pill shows about how an app was reached. `link` is
 * what name resolution produced, or null for bytes that arrived with no
 * address (a dropped file), which are known only by their key.
 */
async function trustOf(link, report) {
  const base = link || { address: addressOfKey(report.id), kind: 'key', rail: 'key', name: null, status: 'self-certifying', publisher: null, publisherKey: null, pinnedAt: null };
  let publisherInfo = null;
  if (base.publisherKey) {
    try {
      const key = base64Decode(base.publisherKey);
      publisherInfo = { name: base.publisher, fingerprint: await fingerprint(key), anchor: await publisherAnchor(base.rail, key) };
    } catch {
      publisherInfo = null;
    }
  }
  const passed = report.steps.filter((step) => step.ok === true).length;
  return {
    ...base,
    id: report.id,
    keyAddress: addressOfKey(report.id),
    fingerprint: await fingerprint(report.publicKey),
    servedAt: keyOrigin(report.id),
    checks: `${passed} of ${report.steps.length}`,
    publisherInfo,
    aliases: pins.namesFor(report.id).filter((name) => name !== base.name).map((name) => `key-web://${name}/`),
    // A petname is yours alone, so the link worth sharing is the key itself.
    shareable: base.kind === 'petname' ? addressOfKey(report.id) : base.address,
  };
}

/**
 * Takes bytes from any transport, verifies them, and opens the app if and
 * only if they verify. Resolves true when the app is running.
 */
async function present(bytes, { transport, expectedId = null, tamperNote = null, link = null }) {
  const token = ++state.opening;
  const report = await inspectSwbn(bytes, { expectedId, maxBytes: MAX_BUNDLE_BYTES });
  if (token !== state.opening) return false;
  const descriptor = readDescriptor(report);
  const tampered = tamperNote !== null;
  const previous = state.loaded;
  state.loaded = {
    bytes,
    report,
    transport,
    expectedId,
    link,
    original: tampered ? previous.original : bytes,
    originalReport: tampered ? previous.originalReport : report,
    originalOk: tampered ? previous.originalOk : report.ok,
  };
  await renderInspector(report, descriptor);
  byId('restore').hidden = !tampered;
  byId('tamper-note').hidden = !tampered;
  byId('tamper-note').textContent = tamperNote || '';
  fill(byId('telemetry'), el('li', { class: 'empty' }, 'Nothing blocked yet.'));
  showNotice('', '');

  if (!report.ok) {
    closeSession();
    showBlocked(`${report.code} — ${FAILURE_TEXT[report.code] || 'verification failed'}!`, report.steps.find((step) => step.ok === false)?.detail || report.message);
    return false;
  }

  await cache.put(report, bytes, { via: transport, name: descriptor.name, version: descriptor.version });
  renderCacheInfo();
  closeSession();
  const judge = petnames.judge(descriptor.name, report.id);
  const trust = await trustOf(link, report);
  if (token !== state.opening) return false;
  const session = { id: report.id, report, descriptor, transport, judge, trust, sandbox: null, ledgerBase: null };
  session.sandbox = new Sandbox({
    container: viewport,
    id: report.id,
    port: location.port,
    protocol: location.protocol,
    title: `${judge.status === 'petname' ? judge.name : descriptor.name || 'Unnamed app'}, sandboxed key origin`,
    onMessage: (message) => onAppMessage(session, message),
    onEvent: (event) => {
      if (event.type !== 'navigation' || state.session !== session) return;
      closeSession();
      showBlocked('NAVIGATION_BLOCKED — the app tried to leave its origin!', 'The app navigated its own frame away from the document that was verified. The frame was closed.');
    },
  });
  state.session = session;
  showStage('none');
  renderChrome();
  if (judge.status === 'impostor') {
    showNotice('bad', `Impersonation warning. This bundle calls itself “${judge.name}”, but your petname “${judge.petname}” belongs to key ${shortId(judge.boundTo)}. This one is signed by ${shortId(report.id)}. It runs as a separate, unnamed origin and sees none of ${judge.petname}'s data.`);
  }
  session.ledgerBase = await readLedger();
  try {
    await session.sandbox.boot(bytes);
  } catch (error) {
    if (state.session !== session) return false;
    closeSession();
    showBlocked(`${error.code || 'SANDBOX_FAILED'} — the app was not opened`, error.message);
    return false;
  }
  if (state.session !== session) return false;
  // How many apps have been opened, and which key is running: a way to tell
  // one boot from the next without reading the address.
  document.documentElement.dataset.booted = String(++state.booted);
  document.documentElement.dataset.running = session.id;
  renderChrome();
  await refreshLedger();
  return true;
}

/** Re-checks every accepted rotation on the way from a key to its current successor. */
async function followRotations(id) {
  const { hops } = rotations.resolve(id);
  let current = id;
  for (const hop of hops) {
    const record = rotations.recordFor(hop.from);
    const check = await verifyRotation(record.certificate, { currentId: hop.from, committedDigest: record.committedDigest, currentSequence: record.sequence - 1 });
    if (!check.ok || check.to !== hop.to) {
      trace.add('Key rotation').fail(`the stored certificate for ${shortId(hop.from)} no longer verifies (${check.code}): staying on the old key`);
      return current;
    }
    trace.note('Key rotation', `${shortId(hop.from)} handed this origin to ${shortId(hop.to)} (sequence ${hop.sequence}, certificate re-verified)`);
    current = hop.to;
  }
  return current;
}

const blockedBy = (code, text) => ({ blocked: { code, text } });

/**
 * Turns a parsed address into a key. For a name on a rail that means: ask
 * the rail, check the record's signature, and then let the pin decide.
 * Resolves with {id, link}, or with {blocked: {code, text}} when the name
 * must not be opened.
 */
async function resolveAddress(parsed) {
  const link = { address: parsed.address, kind: parsed.kind, rail: parsed.rail, name: null, status: 'self-certifying', publisher: null, publisherKey: null, pinnedAt: null };
  if (parsed.kind === 'key') {
    trace.note('Address', 'Self-certifying: the address is the key itself. No resolver was asked.');
    return { id: parsed.id, link };
  }
  if (parsed.kind === 'petname') {
    const entry = petnames.list().find((candidate) => petnameLabel(candidate.name) === parsed.label || nameKey(candidate.name) === nameKey(parsed.label));
    if (!entry) return blockedBy('UNKNOWN_PETNAME — nothing in your petname book has that name', `${parsed.address} is a name from your own petname book, and the book has no such entry. Bind the petname on the second tab first.`);
    trace.note('Petname book', `“${entry.name}” is your petname for ${shortId(entry.id)}. No network was asked.`);
    return { id: entry.id, link: { ...link, status: 'petname' } };
  }

  const rail = RAILS[parsed.rail];
  const name = parsed.host;
  link.name = name;
  link.publisher = parsed.publisher;
  const row = trace.add(`Resolver ${rail.suffix}`);
  let record = null;
  try {
    const checked = await verifyNameRecord(await transports.resolve(parsed.rail, parsed.publisher, parsed.app), parsed);
    if (checked.ok) {
      record = checked;
      row.ok(`${name} → ${shortId(checked.key)}. Record signed by publisher key ${await fingerprint(checked.publisherKey)}.`);
    } else row.fail(`${checked.code}: ${checked.message}`);
  } catch (error) {
    row.fail(`${error.code || 'FAILED'}: ${error.message}`);
  }

  const pin = pins.get(name);
  if (!record) {
    if (!pin) return blockedBy('UNRESOLVED — the name could not be looked up', `The ${rail.suffix} resolver gave no usable answer for ${parsed.address}, and this name has never been used on this machine, so there is no pinned key to fall back on. Try another rail, or the self-certifying .key address.`);
    trace.note('Pin', `The resolver was not needed. ${name} was pinned to ${shortId(pin.key)} on ${new Date(pin.pinnedAt).toLocaleString('en-GB')}, and the pin decides.`);
    return { id: pin.key, link: { ...link, status: 'pinned-offline', publisherKey: pin.publisherKey, pinnedAt: pin.pinnedAt } };
  }

  const publisherKey = base64url(record.publisherKey);
  const verdict = judgeRecord(pin, record.key);
  if (verdict === 'first-use') {
    const made = pins.pin(name, { key: record.key, publisherKey });
    trace.note('Pin', `First use of this name here: ${shortId(record.key)} is now pinned to it (trust on first use).`);
    return { id: record.key, link: { ...link, status: 'first-use', publisherKey, pinnedAt: made.pinnedAt } };
  }
  if (verdict === 'match') {
    pins.seen(name);
    trace.note('Pin', `Same key as pinned on ${new Date(pin.pinnedAt).toLocaleString('en-GB')}.`);
    return { id: record.key, link: { ...link, status: 'match', publisherKey, pinnedAt: pin.pinnedAt } };
  }
  if (verdict === 'stale') {
    trace.note('Pin', `The rail still lists ${shortId(record.key)}, a key this origin has rotated away from. Using the pinned key ${shortId(pin.key)}.`);
    return { id: pin.key, link: { ...link, status: 'stale', publisherKey: pin.publisherKey, pinnedAt: pin.pinnedAt } };
  }

  // The name now points at a different key. A rail saying so proves
  // nothing. Only the pinned key can hand the name on: through rotations
  // already accepted here, or through certificates that verify now.
  trace.add('Pin').fail(`${name} is pinned to ${shortId(pin.key)}, but the rail answers ${shortId(record.key)}.`);
  let current = await followRotations(pin.key);
  if (current !== record.key) {
    for (const certificate of record.certificates) {
      let committed = null;
      try {
        committed = await commitmentFor(current, { cache, fetchBundle });
      } catch {
        committed = null;
      }
      const check = await verifyRotation(certificate, { currentId: current, committedDigest: committed, currentSequence: rotations.sequenceFor(current) });
      if (!check.ok) {
        trace.add('Rotation certificate').fail(`The record came with a certificate, and it does not hold: ${check.code}. ${check.message}`);
        break;
      }
      trace.note('Rotation certificate', `Signed by the pinned key for the successor it committed to in advance: ${shortId(current)} → ${shortId(check.to)}, sequence ${check.sequence}.`);
      await adoptRotation({ fromId: current, report: check, certificate, committedDigest: committed, rotations, petnames, say: (kind, text) => trace.note('Key rotation', text) });
      current = check.to;
      if (current === record.key) break;
    }
  }
  if (current !== record.key) {
    return blockedBy(
      'HANDLE_HIJACK — this name now points at a different key!',
      `${parsed.address} is pinned to key ${shortId(pin.key)}. The ${rail.suffix} resolver now answers ${shortId(record.key)}, and no rotation certificate signed by the pinned key, for a successor it committed to in advance, connects the two. A valid signature under a new key is exactly what a hijacker has. Nothing was opened, and the pinned key's storage was not touched. The app is still reachable on another rail, or at ${addressOfKey(pin.key)}.`,
    );
  }
  pins.follow(name, record.key, { publisherKey });
  return { id: record.key, link: { ...link, status: 'rotated', publisherKey, pinnedAt: pin.pinnedAt } };
}

/** Opens a key-web address. `via` is 'auto', 'http', 'swarm' or 'cache'. */
async function openAddress(text, via = 'auto') {
  showTab('browse');
  const parsed = parseAddress(text);
  if (!parsed) {
    showNotice('bad', 'That is not a key-web address. Try key-web://localpad.lukeinth.at/, or key-web:// followed by a 56-character key ID and .key.');
    return false;
  }
  const token = ++state.opening;
  trace.reset();
  byId('address').value = parsed.address;
  const resolved = await resolveAddress(parsed);
  namesPanel.refresh();
  if (token !== state.opening) return false;
  if (resolved.blocked) {
    closeSession();
    state.loaded = null;
    renderSteps(byId('steps'), []);
    renderVerdict(byId('verdict'), { ok: null, code: null, text: 'The address was not resolved to a key, so no bytes were fetched.' });
    showBlocked(resolved.blocked.code, resolved.blocked.text);
    byId('address').value = parsed.address;
    renderChrome();
    return false;
  }
  const { link } = resolved;
  const id = await followRotations(resolved.id);
  if (token !== state.opening) return false;
  const entry = catalogEntry(id);
  const attempts = {
    http: () => {
      if (!entry) throw Object.assign(new Error('no mirror is known for this key'), { code: 'NO_MIRROR' });
      return transports.http(entry.file);
    },
    swarm: () => transports.swarm(id, { poisonPeer: byId('poison').checked ? 1 : null, onEvent: (event) => trace.swarm(event) }),
    cache: () => transports.offline(id),
  };
  let delivered = null;
  for (const kind of via === 'auto' ? ['http', 'swarm', 'cache'] : [via]) {
    const row = trace.add(TRANSPORT_LABEL[kind]);
    try {
      const result = await attempts[kind]();
      if (token !== state.opening) return false;
      row.ok(`${bytesText(result.bytes.length)}. ${result.detail}`);
      delivered = { kind, bytes: result.bytes };
      break;
    } catch (error) {
      if (token !== state.opening) return false;
      row.fail(`${error.code || 'FAILED'}: ${error.message}`);
    }
  }
  if (!delivered) {
    closeSession();
    state.loaded = null;
    renderSteps(byId('steps'), []);
    renderVerdict(byId('verdict'), { ok: null, code: null, text: 'No bytes arrived, so there was nothing to verify.' });
    showBlocked('UNREACHABLE — no transport delivered this key', 'Every transport that was tried failed. Open the app once while any transport works and it will be in the offline cache.');
    byId('address').value = parsed.address;
    renderChrome();
    return false;
  }
  return present(delivered.bytes, { transport: delivered.kind, expectedId: id, link });
}

/** Opens a key by its ID alone, through its self-certifying address. */
const openLink = (id, via = 'auto') => openAddress(addressOfKey(id), via);

/** Opens bytes that arrived with no link: a dropped file or pasted text. */
function openBytes(bytes, transport, label) {
  showTab('browse');
  trace.reset();
  trace.add(label).ok(`${bytesText(bytes.length)}. No server was involved; the bytes name their own key.`);
  return present(bytes, { transport, expectedId: null });
}

// ---------------------------------------------------------------- tampering

function tamper() {
  const loaded = state.loaded;
  if (!loaded || !loaded.originalOk) return;
  const original = loaded.original;
  const start = loaded.originalReport.integrityBlockLength;
  const offset = start + 64 + Math.floor(Math.random() * Math.max(1, original.length - start - 128));
  const copy = original.slice();
  const before = copy[offset];
  copy[offset] ^= 1 << Math.floor(Math.random() * 8);
  let where = 'the bundle structure';
  for (const [path, exchange] of loaded.originalReport.exchanges) {
    const from = exchange.payload.byteOffset - original.byteOffset;
    if (offset >= from && offset < from + exchange.payload.length) where = path;
  }
  const byte = (value) => `0x${value.toString(16).padStart(2, '0')}`;
  const note = `Flipped one bit: byte ${offset.toLocaleString('en-US')} of ${original.length.toLocaleString('en-US')} went from ${byte(before)} to ${byte(copy[offset])}, inside ${where}. Everything else is identical.`;
  trace.add('Attacker in the middle').fail(`one bit changed in transit, at byte ${offset.toLocaleString('en-US')}`);
  present(copy, { transport: loaded.transport, expectedId: loaded.expectedId, tamperNote: note, link: loaded.link });
}

function restore() {
  const loaded = state.loaded;
  if (!loaded) return;
  trace.note('Restored', 'the original bytes, exactly as they were delivered');
  present(loaded.original, { transport: loaded.transport, expectedId: loaded.expectedId, link: loaded.link });
}

// ---------------------------------------------------------------- the rail

function renderCacheInfo() {
  const entries = cache.list();
  const total = entries.reduce((sum, entry) => sum + (entry.size || 0), 0);
  byId('cache-info').textContent = entries.length ? `Offline cache: ${entries.length} verified bundle${entries.length === 1 ? '' : 's'}, ${bytesText(total)}` : 'Offline cache: empty';
}

function renderLinks() {
  const apps = state.catalog.apps.filter((app) => app.role === 'app');
  if (apps.length === 0) {
    fill(byId('links'), el('li', { class: 'empty' }, 'The signed demo bundles are missing. Run "node scripts/build-swbn.mjs" and reload.'));
    return;
  }
  fill(byId('links'), apps.map((app) => {
    const current = rotations.resolve(app.id).id;
    const petname = petnames.nameFor(current);
    // Every address this app can be reached by: its readable names, one per
    // rail, and the key itself. The first is the one the buttons below use.
    const addresses = [
      ...state.catalog.names.filter((name) => name.slug === app.slug).map((name) => ({ address: `key-web://${name.name}/`, shown: `key-web://${name.name}/`, rail: name.rail })),
      { address: addressOfKey(app.id), shown: `key-web://${shortId(app.id)}.key/`, rail: 'key' },
    ];
    const primary = addresses[0].address;
    const via = (kind, text) => el('button', { type: 'button', class: 'btn btn-small', dataset: { open: app.id, via: kind }, onclick: () => openAddress(primary, kind) }, text);
    const linkRow = ({ address, shown, rail }) => el('li', { class: 'link-row' },
      el('a', {
        class: 'link-url mono',
        href: address,
        title: address,
        dataset: { address, rail },
        onclick: (event) => {
          event.preventDefault();
          openAddress(address, 'auto');
        },
      }, shown),
      el('button', {
        type: 'button',
        class: 'link-button link-copy',
        'aria-label': `Copy ${address}`,
        dataset: { copy: address },
        onclick: (event) => copyLink(event.currentTarget, address),
      }, 'Copy'),
    );
    return el('li', { class: 'link-card', dataset: { slug: app.slug } },
      el('div', { class: 'link-head' },
        el('strong', {}, petname || app.name),
        el('span', { class: `tag ${petname ? 'tag-petname' : 'tag-claim'}` }, petname ? 'your petname' : 'self-declared'),
        el('span', { class: 'link-version' }, `v${app.version}`),
      ),
      el('p', { class: 'link-summary' }, app.summary),
      el('ul', { class: 'link-list' }, addresses.map(linkRow)),
      current !== app.id ? el('p', { class: 'link-rotated' }, `Key rotated: now ${shortId(current)}`) : null,
      el('div', { class: 'link-via' }, via('http', 'HTTP mirror'), via('swarm', 'P2P swarm'), via('cache', 'Offline cache')),
      el('div', { class: 'link-extra' },
        el('a', { href: transports.mirrorUrl(app.file), rel: 'noopener' }, 'Download .swbn'),
        el('button', {
          type: 'button',
          class: 'link-button',
          dataset: { base64: app.id },
          onclick: async () => {
            try {
              const bytes = new Uint8Array(await (await fetchSelf(`demo-bundles/${app.file}`)).arrayBuffer());
              byId('paste').value = base64(bytes);
              byId('paste').focus();
            } catch (error) {
              showNotice('bad', `Could not read the bundle: ${error.message}`);
            }
          },
        }, 'Put it in the paste box as base64'),
      ),
    );
  }));
}

function wireRail() {
  const zone = byId('dropzone');
  const input = byId('file-input');
  const take = async (file) => {
    if (!file) return;
    if (file.size > MAX_BUNDLE_BYTES) {
      showNotice('bad', 'That file is larger than a bundle may be.');
      return;
    }
    await openBytes(new Uint8Array(await file.arrayBuffer()), 'file', `File drop: ${file.name.slice(0, 60)}`);
  };
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      input.click();
    }
  });
  input.addEventListener('change', () => {
    take(input.files[0]);
    input.value = '';
  });
  for (const type of ['dragenter', 'dragover']) {
    zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.add('dropzone-over');
    });
  }
  zone.addEventListener('dragleave', () => zone.classList.remove('dropzone-over'));
  zone.addEventListener('drop', (event) => {
    event.preventDefault();
    zone.classList.remove('dropzone-over');
    take(event.dataTransfer.files[0]);
  });
  // A file dropped beside the zone must not navigate the runner away.
  for (const type of ['dragover', 'drop']) window.addEventListener(type, (event) => event.preventDefault());

  byId('paste-load').addEventListener('click', () => {
    let bytes;
    try {
      bytes = base64Decode(byId('paste').value);
    } catch {
      showNotice('bad', 'That is not base64.');
      return;
    }
    openBytes(bytes, 'paste', 'Pasted base64');
  });
  byId('paste-clear').addEventListener('click', () => {
    byId('paste').value = '';
  });
  byId('cache-clear').addEventListener('click', async () => {
    await cache.clear();
    renderCacheInfo();
  });
}

// ---------------------------------------------------------------- start

async function start() {
  byId('tab-browse').addEventListener('click', () => showTab('browse'));
  byId('tab-names').addEventListener('click', () => showTab('names'));
  byId('net-toggle').addEventListener('click', toggleNetwork);
  byId('tamper').addEventListener('click', tamper);
  byId('restore').addEventListener('click', restore);
  byId('close').addEventListener('click', () => {
    closeSession();
    showStage('start');
  });
  byId('reload').addEventListener('click', () => {
    if (state.loaded && state.loaded.report.ok) present(state.loaded.bytes, { transport: state.loaded.transport, expectedId: state.loaded.expectedId, link: state.loaded.link });
  });
  byId('omnibox').addEventListener('submit', (event) => {
    event.preventDefault();
    openAddress(byId('address').value, 'auto');
  });
  byId('copy-link').addEventListener('click', () => {
    if (state.session) copyLink(byId('copy-link'), state.session.trust.shareable);
  });
  const showTrust = (open) => {
    trustNodes.panel.hidden = !open;
    trustNodes.pill.setAttribute('aria-expanded', String(open));
  };
  trustNodes.pill.addEventListener('click', () => showTrust(trustNodes.panel.hidden));
  byId('trust-close').addEventListener('click', () => showTrust(false));
  byId('trust-copy-name').addEventListener('click', () => {
    if (state.session) copyLink(byId('trust-copy-name'), state.session.trust.shareable);
  });
  byId('trust-copy-key').addEventListener('click', () => {
    if (state.session) copyLink(byId('trust-copy-key'), state.session.trust.keyAddress);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !trustNodes.panel.hidden) {
      showTrust(false);
      trustNodes.pill.focus();
    }
  });
  for (const button of document.querySelectorAll('button[data-open-address]')) {
    button.addEventListener('click', () => openAddress(button.dataset.openAddress, 'auto'));
  }
  byId('grant-deny').addEventListener('click', () => decideGrant(null));
  byId('grant-once').addEventListener('click', () => decideGrant('once'));
  byId('grant-timed').addEventListener('click', () => decideGrant('timed'));
  wireRail();

  try {
    const catalog = await (await fetchSelf('demo-bundles/catalog.json')).json();
    if (catalog && Array.isArray(catalog.apps)) state.catalog = { ...catalog, names: Array.isArray(catalog.names) ? catalog.names : [] };
  } catch {
    showNotice('bad', 'The signed demo bundles are not built yet. Run "node scripts/build-swbn.mjs", then reload.');
  }

  namesPanel = initNames({
    state, petnames, rotations, pins, cache, fetchSelf, fetchBundle, openLink, openAddress, openBytes, showNotice,
    onChange: () => {
      renderLinks();
      if (state.session) {
        state.session.judge = petnames.judge(state.session.descriptor.name, state.session.id);
        renderChrome();
      }
    },
  });

  renderLinks();
  renderCacheInfo();
  renderChrome();
  await readNetwork();
  if (state.api) {
    try {
      state.telemetrySeq = (await (await fetch('api/telemetry?since=999999999', { cache: 'no-store' })).json()).seq;
    } catch {
      state.telemetrySeq = 0;
    }
  }
  await refreshLedger();
  await namesPanel.refresh();

  setInterval(() => {
    if (state.session) pollTelemetry();
  }, 700);
  setInterval(() => {
    if (state.session && grants.list(state.session.id).length !== byId('grants').querySelectorAll('.grant-row').length) renderChrome();
    else if (state.session && grants.list(state.session.id).some((grant) => grant.mode === 'timed')) renderChrome();
  }, 1000);
  setInterval(refreshLedger, 2500);
  document.documentElement.dataset.ready = 'true';
}

start();
