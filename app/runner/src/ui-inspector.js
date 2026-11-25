// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The inspector column: what was fetched and how, each verification step,
// what the bundle is, what the sandbox blocked, and what was granted.

import { bytesText, clear, clock, el, fill } from './dom.js';
import { hex } from './engine/bytes.js';
import { CAPABILITIES } from './capabilities.js';

const MARK = { true: '✓', false: '✗', null: '·' };

/** Renders a list of {label, ok, detail} checks, for bundles and for rotation certificates alike. */
export function renderSteps(list, steps) {
  fill(list, steps.map((step) => el('li', { class: `step step-${step.ok === true ? 'ok' : step.ok === false ? 'fail' : 'skip'}` },
    el('span', { class: 'step-mark', 'aria-hidden': 'true' }, MARK[String(step.ok)]),
    el('span', { class: 'step-body' },
      el('span', { class: 'step-label' }, step.label),
      step.detail ? el('span', { class: 'step-detail' }, step.detail) : null,
    ),
    el('span', { class: 'visually-hidden' }, step.ok === true ? 'passed' : step.ok === false ? 'failed' : 'not reached'),
  )));
}

export function renderVerdict(node, { ok, code, text }) {
  node.className = `verdict ${ok === true ? 'verdict-ok' : ok === false ? 'verdict-fail' : 'verdict-idle'}`;
  fill(node, code ? el('strong', {}, code) : null, code ? ' ' : null, text);
}

/** The transport panel: one row per attempt, plus the swarm's chunk grid. */
export function createTrace(list, swarmBox, grid) {
  let cells = [];
  const row = (label) => {
    const state = el('span', { class: 'trace-state' }, 'trying');
    const detail = el('span', { class: 'trace-detail' });
    const item = el('li', { class: 'trace-row trace-trying' }, el('span', { class: 'trace-label' }, label), state, detail);
    if (list.querySelector('.empty')) clear(list);
    list.append(item);
    const settle = (kind, word, text) => {
      item.className = `trace-row trace-${kind}`;
      state.textContent = word;
      detail.textContent = text;
    };
    return {
      ok: (text) => settle('ok', 'delivered', text),
      fail: (text) => settle('fail', 'failed', text),
      info: (text) => settle('info', 'note', text),
    };
  };
  return {
    reset() {
      fill(list);
      swarmBox.hidden = true;
      clear(grid);
      cells = [];
    },
    add: row,
    note(label, text) {
      row(label).info(text);
    },
    /** Feeds one event from the swarm download into the chunk grid. */
    swarm(event) {
      if (event.type === 'manifest') {
        swarmBox.hidden = false;
        cells = event.manifest.chunks.map((hash, index) => el('span', { class: 'chunk chunk-waiting', title: `chunk ${index}: waiting` }, String(index)));
        fill(grid, cells);
        return;
      }
      const cell = cells[event.index];
      if (!cell) return;
      if (event.status === 'ok') {
        const caught = cell.classList.contains('chunk-caught');
        cell.className = `chunk peer-${event.peer + 1}${caught ? ' chunk-caught' : ''}`;
        cell.title = `chunk ${event.index}: ${event.bytes} bytes from peer ${event.peer + 1}, hash verified${caught ? ' (after a poisoned copy was thrown away)' : ''}`;
      } else if (event.status === 'poisoned') {
        cell.className = 'chunk peer-bad chunk-caught';
        cell.title = `chunk ${event.index}: peer ${event.peer + 1} sent bytes that do not match the chunk's hash`;
        row(`Chunk ${event.index}`).fail(`peer ${event.peer + 1} served a corrupted chunk: SHA-256 mismatch. Peer ${event.peer + 1} dropped, re-fetching from the next peer.`);
      } else {
        cell.title = `chunk ${event.index}: peer ${event.peer + 1} did not answer`;
      }
    },
  };
}

const fact = (term, value, mono = true) => [el('dt', {}, term), el('dd', { class: mono ? 'mono' : '' }, value)];

/** The bundle panel, for a bundle that verified. */
export function renderFacts(list, resourceList, resourceSummary, { report, descriptor, servedAt, fingerprint }) {
  if (!report || report.ok !== true) {
    fill(list, fact('Origin', 'none: the bytes did not verify', false));
    fill(resourceList);
    resourceSummary.textContent = 'Resources';
    return;
  }
  const signature = report.signatures[0];
  fill(list,
    fact('Origin', report.origin),
    fact('Same bytes in Chromium', report.iwaOrigin),
    fact('Served at', servedAt),
    fact('Ed25519 public key', hex(report.publicKey)),
    fact('Key fingerprint', fingerprint),
    fact('Signature', `${hex(signature.signature).slice(0, 48)}…`),
    fact('File', `${bytesText(report.size)} (${report.integrityBlockLength} B integrity block + ${bytesText(report.bundleLength)} payload)`, false),
    fact('SHA-256', report.sha256),
    fact('Says it is', descriptor.name ? `“${descriptor.name}” ${descriptor.version || ''} (a claim, signed by this key)` : 'nothing', false),
    fact('Declares capabilities', descriptor.capabilities.length ? descriptor.capabilities.join(', ') : 'none', false),
    fact('Next key committed', descriptor.nextKeyDigest || 'none'),
  );
  resourceSummary.textContent = `Resources (${report.paths.length})`;
  fill(resourceList, report.paths.map((path) => {
    const exchange = report.exchanges.get(path);
    return el('li', {}, el('span', { class: 'mono' }, path), el('span', { class: 'resource-meta' }, `${exchange.headers['content-type']}, ${bytesText(exchange.payload.length)}`));
  }));
}

/** Adds one blocked request to the telemetry list. */
export function addTelemetry(list, { at, directive, blocked, source }) {
  if (list.querySelector('.empty')) clear(list);
  list.prepend(el('li', { class: 'telemetry-row' },
    el('span', { class: 'telemetry-time mono' }, clock(at)),
    el('span', { class: 'telemetry-verb' }, 'BLOCKED'),
    el('span', { class: 'telemetry-directive mono' }, directive || 'policy'),
    el('span', { class: 'telemetry-target mono' }, blocked || '(inline)'),
    source === 'app' ? el('span', { class: 'telemetry-source' }, 'reported by the app') : null,
  ));
  while (list.children.length > 60) list.lastElementChild.remove();
}

function remaining(ms) {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

/** The live grants of the open app, with a way to take each one back. */
export function renderGrants(list, grants, now, onRevoke) {
  if (grants.length === 0) {
    fill(list, el('li', { class: 'empty' }, 'Tier 0. Nothing granted.'));
    return;
  }
  fill(list, grants.map((grant) => el('li', { class: 'grant-row' },
    el('span', { class: 'grant-name' }, el('strong', { class: 'mono' }, grant.capability), el('span', {}, CAPABILITIES[grant.capability].title)),
    el('span', { class: 'grant-life' }, grant.mode === 'once' ? 'one use left' : `${remaining(grant.expires - now)} left`),
    el('button', { type: 'button', class: 'btn btn-quiet', onclick: () => onRevoke(grant) }, 'Revoke'),
  )));
}

export function addLog(list, kind, text) {
  list.prepend(el('li', { class: `log log-${kind}` }, el('span', { class: 'mono log-time' }, clock()), el('span', {}, text)));
  while (list.children.length > 40) list.lastElementChild.remove();
}

export { remaining };
