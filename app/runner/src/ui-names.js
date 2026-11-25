// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The second tab: readable names and the rails that resolve them, the pins
// that decide, the petname book, the impersonation test, and the key
// rotation simulator.

import { byId, el, fill } from './dom.js';
import { NETWORK_RAILS, addressOfKey } from './engine/names.js';
import { ROTATION_FAILURE_TEXT, verifyRotation } from './engine/rotation.js';
import { fingerprint, idFromLink, keyFromId, shortId } from './engine/swbn.js';
import { adoptRotation, commitmentFor } from './rotate.js';
import { addLog, renderSteps, renderVerdict } from './ui-inspector.js';

export function initNames({ state, petnames, rotations, pins, cache, fetchSelf, fetchBundle, openLink, openAddress, openBytes, showNotice, onChange }) {
  const find = (slug, role) => state.catalog.apps.find((app) => app.slug === slug && app.role === role) || null;
  const original = () => find('localpad', 'app');
  const impostor = () => state.catalog.apps.find((app) => app.role === 'impostor') || null;
  const fingerprints = new Map();
  const rails = Object.fromEntries(NETWORK_RAILS.map((rail) => [rail, { down: false, mode: 'normal' }]));
  let control = false;
  let committed = null;

  const message = (kind, text) => {
    const node = byId('petname-message');
    node.hidden = !text;
    node.className = `message message-${kind}`;
    node.textContent = text || '';
  };

  const railMessage = (kind, text) => {
    const node = byId('rail-message');
    node.hidden = !text;
    node.className = `message message-${kind}`;
    node.textContent = text || '';
  };

  async function fingerprintOf(id) {
    if (!fingerprints.has(id)) fingerprints.set(id, await fingerprint(keyFromId(id)));
    return fingerprints.get(id);
  }

  // ---------------------------------------------------------------- rails and pins

  /** The name the hijack demo is about: the first readable name of LocalPad on the .at rail. */
  const hijackedName = () => {
    const hijack = state.catalog.hijack;
    const app = original();
    if (!hijack || !app) return null;
    const entry = state.catalog.names.find((name) => name.publisher === hijack.publisher && name.rail === hijack.rail && name.slug === app.slug);
    return entry ? entry.name : null;
  };

  function renderRails() {
    const describe = (rail) => {
      const { down, mode } = rails[rail];
      if (!control) return ['rail-state', 'needs the dev server'];
      if (down) return ['rail-state rail-down', 'DOWN: connections are dropped'];
      if (mode === 'hijacked') return ['rail-state rail-down', 'HIJACKED: lukeinth answers with an attacker\'s key'];
      if (mode === 'rotated') return ['rail-state rail-changed', 'publishing LocalPad\'s rotated key, with its certificate'];
      return ['rail-state rail-up', 'up, answering honestly'];
    };
    for (const rail of NETWORK_RAILS) {
      const node = byId(`rail-${rail}-state`);
      const [className, text] = describe(rail);
      node.className = className;
      node.textContent = text;
      node.dataset.down = String(rails[rail].down);
      node.dataset.mode = rails[rail].mode;
      const kill = byId(`rail-${rail}-kill`);
      kill.disabled = !control;
      kill.textContent = rails[rail].down ? `Revive the .${rail} resolver` : `Kill the .${rail} resolver`;
      kill.className = rails[rail].down ? 'btn btn-primary' : 'btn btn-danger';
    }
    const hijack = byId('rail-at-hijack');
    hijack.disabled = !control;
    hijack.textContent = rails.at.mode === 'hijacked' ? 'End the hijack (lukeinth.at answers honestly again)' : 'Simulate handle hijack (lukeinth.at → evil key)';
    hijack.className = rails.at.mode === 'hijacked' ? 'btn btn-primary' : 'btn btn-danger';
    const rotate = byId('rail-at-rotate');
    rotate.disabled = !control;
    rotate.textContent = rails.at.mode === 'rotated' ? 'Withdraw the rotation record from .at' : 'Publish the signed key rotation on .at';
  }

  async function readRails() {
    try {
      const answer = await (await fetch('api/rails', { cache: 'no-store' })).json();
      control = answer.control === true;
      for (const rail of NETWORK_RAILS) if (answer.rails && answer.rails[rail]) Object.assign(rails[rail], answer.rails[rail]);
    } catch {
      // No dev server, so no rails to control: names resolve from pins only.
      control = false;
    }
    renderRails();
  }

  async function setRail(rail, change) {
    try {
      const response = await fetch('api/rails', { method: 'POST', headers: { 'X-KeyWeb-Control': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ rail, ...change }) });
      const answer = await response.json();
      if (!response.ok) throw new Error(answer.error || 'refused');
      for (const name of NETWORK_RAILS) Object.assign(rails[name], answer.rails[name]);
    } catch (error) {
      railMessage('bad', `Could not change the .${rail} resolver: ${error.message}`);
    }
    renderRails();
  }

  async function renderPins() {
    const entries = pins.list();
    if (entries.length === 0) {
      fill(byId('pin-rows'), el('tr', {}, el('td', { colspan: '4', class: 'empty' }, 'Nothing pinned yet. Open a readable name and the key it resolves to is pinned here.')));
      return;
    }
    const rows = [];
    for (const pin of entries) {
      rows.push(el('tr', { dataset: { pin: pin.name, key: pin.key } },
        el('td', { class: 'mono' }, `key-web://${pin.name}/`),
        el('td', { class: 'mono', title: addressOfKey(pin.key) }, await fingerprintOf(pin.key), pin.previous.length ? el('span', { class: 'row-note' }, `rotated ${pin.previous.length} time${pin.previous.length === 1 ? '' : 's'}`) : null),
        el('td', {}, new Date(pin.pinnedAt).toLocaleString('en-GB')),
        el('td', {}, el('button', {
          type: 'button',
          class: 'btn btn-quiet',
          onclick: () => {
            pins.unpin(pin.name);
            railMessage('info', `${pin.name} is unpinned. The next key it resolves to will be trusted as if for the first time, so only do this when you are sure of the rail.`);
            renderPins();
          },
        }, 'Unpin')),
      ));
    }
    fill(byId('pin-rows'), rows);
  }

  // ---------------------------------------------------------------- petnames

  async function renderRows() {
    const entries = petnames.list();
    if (entries.length === 0) {
      fill(byId('petname-rows'), el('tr', {}, el('td', { colspan: '4', class: 'empty' }, 'No petnames yet. Every app is shown by the name it gives itself, marked as a claim.')));
      return;
    }
    const rows = [];
    for (const entry of entries) {
      rows.push(el('tr', { dataset: { petname: entry.name } },
        el('td', {}, el('strong', {}, entry.name), entry.note ? el('span', { class: 'row-note' }, entry.note) : null),
        el('td', { class: 'mono' }, await fingerprintOf(entry.id)),
        el('td', { class: 'mono', title: addressOfKey(entry.id) }, `key-web://${shortId(entry.id)}.key/`),
        el('td', {}, el('button', {
          type: 'button',
          class: 'btn btn-quiet',
          onclick: () => {
            petnames.unbind(entry.id);
            message('info', `“${entry.name}” is unbound. That key is a stranger again.`);
            renderRows();
            onChange();
          },
        }, 'Unbind')),
      ));
    }
    fill(byId('petname-rows'), rows);
  }

  function bind(name, keyText) {
    const id = idFromLink(keyText);
    if (!id) {
      message('bad', 'That is not a key. Paste a key-web:// link that ends in .key, or a 56-character key ID.');
      return false;
    }
    const result = petnames.bind(name, id);
    if (!result.ok) {
      if (result.code === 'COLLISION') {
        message('bad', `Collision. “${result.existing.name}” is already your petname for key ${shortId(result.existing.id)}. A different key, ${shortId(id)}, is asking for the same name, which is exactly what an impersonator would do. Nothing was changed. Unbind the existing petname first if you really mean to move it.`);
      } else if (result.code === 'EMPTY_NAME') message('bad', 'A petname needs at least one letter or digit.');
      else message('bad', 'That key ID is not a valid Ed25519 key origin.');
      return false;
    }
    message('ok', `Bound. On this machine “${result.entry.name}” now means key ${shortId(id)}, whichever transport its bundle arrives by.`);
    renderRows();
    onChange();
    return true;
  }

  // ---------------------------------------------------------------- rotation

  async function renderRotation() {
    const app = original();
    if (!app) {
      fill(byId('rotation-state'), el('dt', {}, 'LocalPad'), el('dd', {}, 'not built'));
      return;
    }
    try {
      // Read from LocalPad's own bundle after verifying the old key signed it.
      committed = await commitmentFor(app.id, { cache, fetchBundle });
    } catch {
      committed = null;
    }
    const record = rotations.recordFor(app.id);
    const now = rotations.resolve(app.id).id;
    fill(byId('rotation-state'),
      el('dt', {}, 'Origin, key 1'), el('dd', { class: 'mono', title: app.id }, `key-web://${shortId(app.id)}.key/`),
      el('dt', {}, 'Next key committed'), el('dd', { class: 'mono' }, committed || 'none found in the signed bundle'),
      el('dt', {}, 'Accepted rotation'), el('dd', { class: record ? 'mono' : '' }, record ? `sequence ${record.sequence}: the origin now belongs to ${shortId(record.to)}` : 'none: key 1 still holds the origin'),
      el('dt', {}, 'Petname'), el('dd', {}, petnames.nameFor(now) ? `“${petnames.nameFor(now)}”, bound to ${shortId(now)}` : 'none bound'),
    );
  }

  async function apply(kind) {
    const app = original();
    const path = state.catalog.rotation && state.catalog.rotation.certificates[kind];
    if (!app || !path) return;
    const log = byId('rotation-log');
    let certificate;
    try {
      certificate = await (await fetchSelf(`demo-bundles/${path}`)).json();
      committed = await commitmentFor(app.id, { cache, fetchBundle });
    } catch (error) {
      showNotice('bad', `Could not load the certificate: ${error.message}`);
      return;
    }
    byId('rotation-certificate').textContent = JSON.stringify(certificate, null, 2);
    const report = await verifyRotation(certificate, { currentId: app.id, committedDigest: committed, currentSequence: rotations.sequenceFor(app.id) });
    renderSteps(byId('rotation-steps'), report.steps);
    renderVerdict(byId('rotation-verdict'), report.ok
      ? { ok: true, code: report.code, text: `Key 1 handed the origin to ${shortId(report.to)}, the key it committed to in advance.` }
      : { ok: false, code: report.code, text: `${ROTATION_FAILURE_TEXT[report.code] || 'rejected'}. Nothing changed.` });
    byId('rotation-verdict').dataset.kind = kind;
    if (!report.ok) {
      addLog(log, 'bad', `${kind}: rejected (${report.code}). The origin stays where it was and no data moved.`);
      return;
    }
    addLog(log, 'ok', `${kind}: accepted. ${shortId(app.id)} → ${shortId(report.to)}, sequence ${report.sequence}.`);
    const outcome = await adoptRotation({ fromId: app.id, report, certificate, committedDigest: committed, rotations, petnames, say: (tone, text) => addLog(log, tone, text) });
    if (!outcome.failed) log.dataset.migrated = String(outcome.migrated);
    await refresh();
    onChange();
  }

  async function refresh() {
    await renderPins();
    await renderRows();
    await renderRotation();
  }

  // ---------------------------------------------------------------- wiring

  for (const rail of NETWORK_RAILS) {
    byId(`rail-${rail}-kill`).addEventListener('click', async () => {
      const down = !rails[rail].down;
      await setRail(rail, { down });
      railMessage('info', down
        ? `The .${rail} resolver is down. A name you have already used still opens: it is pinned, and the pin never needed the resolver. A name you have never used cannot be looked up there.`
        : `The .${rail} resolver is back.`);
    });
  }
  byId('rail-at-hijack').addEventListener('click', async () => {
    const hijacking = rails.at.mode !== 'hijacked';
    await setRail('at', { mode: hijacking ? 'hijacked' : 'normal' });
    if (!hijacking) {
      railMessage('info', 'The hijack is over: lukeinth.at answers with the real key again.');
      return;
    }
    const name = hijackedName();
    const pinned = name ? pins.get(name) : null;
    railMessage(pinned ? 'bad' : 'info', pinned
      ? `lukeinth.at is hijacked: the .at rail now answers with an attacker's key, in a record with a perfectly valid signature by the attacker. Open key-web://${name}/ and watch the pin refuse it.`
      : `lukeinth.at is hijacked. Careful: ${name ? `key-web://${name}/` : 'that name'} has never been opened in this browser, so there is no pin, and the first key a name resolves to is the one that gets pinned. End the hijack, open the name once, then hijack it again to see the pin refuse the swap.`);
  });
  byId('rail-at-rotate').addEventListener('click', async () => {
    const publishing = rails.at.mode !== 'rotated';
    await setRail('at', { mode: publishing ? 'rotated' : 'normal' });
    railMessage('info', publishing
      ? 'The .at rail now answers LocalPad with its new key and the rotation certificate signed by the old one. A name is allowed to change keys this way, and only this way.'
      : 'The .at rail answers with the original key again.');
  });

  byId('petname-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (bind(byId('petname-name').value, byId('petname-key').value)) {
      byId('petname-name').value = '';
      byId('petname-key').value = '';
    }
  });
  byId('petname-current').addEventListener('click', () => {
    if (!state.session) {
      message('info', 'No app is open. Open one on the Browse tab first.');
      return;
    }
    byId('petname-key').value = state.session.trust.keyAddress;
    if (!byId('petname-name').value) byId('petname-name').value = state.session.descriptor.name || '';
    byId('petname-name').focus();
  });
  byId('quick-bind').addEventListener('click', () => {
    const app = original();
    if (app) bind('LocalPad', rotations.resolve(app.id).id);
  });
  byId('bind-impostor').addEventListener('click', () => {
    const fake = impostor();
    if (fake) bind('LocalPad', fake.id);
  });
  byId('open-impostor').addEventListener('click', async () => {
    const fake = impostor();
    if (!fake) return;
    try {
      const bytes = new Uint8Array(await (await fetchSelf(`demo-bundles/${fake.file}`)).arrayBuffer());
      await openBytes(bytes, 'file', 'Impostor bundle, handed over out of band');
    } catch (error) {
      showNotice('bad', `Could not load the impostor bundle: ${error.message}`);
    }
  });
  for (const button of document.querySelectorAll('[data-certificate]')) {
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await apply(button.dataset.certificate);
      } finally {
        button.disabled = false;
      }
    });
  }
  byId('rotation-open').addEventListener('click', () => {
    const app = original();
    if (app) openLink(app.id, 'auto');
  });
  byId('rotation-reset').addEventListener('click', async () => {
    rotations.reset();
    addLog(byId('rotation-log'), 'info', 'Accepted rotations forgotten. Petnames, pins and stored data were left as they are.');
    await refresh();
    onChange();
  });

  readRails();
  return { refresh, readRails, openAddress };
}
