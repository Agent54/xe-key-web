// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The trust pill beside the address, and the panel it opens: which rail the
// name came from, which key it is pinned to, and what was actually checked.

import { el, fill } from './dom.js';
import { RAILS } from './engine/names.js';

const WORD = Object.freeze({
  'first-use': 'pinned now',
  match: 'pinned',
  'pinned-offline': 'pinned',
  stale: 'pinned',
  rotated: 'pinned',
  'self-certifying': 'self-certifying',
  petname: 'petname',
});

const date = (at) => (at ? new Date(at).toLocaleString('en-GB') : 'an earlier visit');

/** What the resolution of this address amounted to, in a sentence. */
function story(trust) {
  switch (trust.status) {
    case 'first-use':
      return 'First use of this name on this machine. The key the rail answered with is pinned now. From here on, the name can only move to another key with a rotation certificate this key committed to in advance.';
    case 'match':
      return `The rail answered with the key this name was pinned to on ${date(trust.pinnedAt)}.`;
    case 'pinned-offline':
      return `The rail could not be reached, and it was not needed: the name was pinned on ${date(trust.pinnedAt)}, and the pin is what decides.`;
    case 'stale':
      return 'The rail still lists an older key of this origin. The rotated key you already accepted was used instead.';
    case 'rotated':
      return 'The rail answered with a new key, together with a rotation certificate signed by the pinned key for a successor it had committed to. The certificate held, so the pin followed.';
    case 'petname':
      return 'Resolved from your own petname book. No network was asked, and nobody else can change what this name means.';
    default:
      return 'The address is the key. There was nothing to resolve, so there is nothing to hijack.';
  }
}

const fact = (term, value, mono = true) => [el('dt', {}, term), el('dd', { class: mono ? 'mono' : '' }, value)];

/**
 * Draws the pill and fills the panel. `trust` is null when no app is open.
 * nodes: {pill, panel, summary, facts}.
 */
export function renderTrust(nodes, trust) {
  const { pill, panel, summary, facts } = nodes;
  if (!trust) {
    pill.hidden = true;
    panel.hidden = true;
    pill.setAttribute('aria-expanded', 'false');
    return;
  }
  const rail = RAILS[trust.rail];
  pill.hidden = false;
  pill.className = `trust-pill ${trust.status === 'first-use' ? 'trust-new' : 'trust-ok'}`;
  pill.dataset.rail = trust.rail;
  pill.dataset.status = trust.status;
  pill.dataset.key = trust.id;
  pill.title = 'How this address was trusted';
  fill(pill,
    el('span', { class: 'trust-rail mono' }, rail.suffix),
    el('span', { class: 'trust-mark', 'aria-hidden': 'true' }, '✓'),
    el('span', {}, WORD[trust.status] || 'verified'),
    el('span', { class: 'trust-print mono' }, trust.fingerprint.slice(0, 9)),
  );
  summary.textContent = story(trust);
  fill(facts,
    fact('Address', trust.address),
    fact('Rail', `${rail.suffix}  ${rail.title}`, false),
    trust.publisherInfo ? fact('Publisher', `${trust.publisherInfo.name}: record signed by key ${trust.publisherInfo.fingerprint}`, false) : null,
    trust.publisherInfo ? fact('Publisher on this rail', trust.publisherInfo.anchor) : null,
    fact(trust.kind === 'name' ? 'Pinned Ed25519 key' : 'Ed25519 key', `${trust.fingerprint}  (${trust.id})`),
    fact('Self-certifying address', trust.keyAddress),
    fact('Bundle signature', `Ed25519, verified in this page: ${trust.checks} checks passed`, false),
    fact('Runs at', trust.servedAt),
    fact('Other names pinned to this key', trust.aliases.length ? trust.aliases.join('  ') : 'none'),
  );
}
