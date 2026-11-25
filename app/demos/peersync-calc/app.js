// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// PeerSync Calc: a calculator that keeps a tape. It boots in Tier 0 like
// every other app. Syncing the tape and exporting it each need one narrow
// capability, which this app declares in its signed descriptor and then has
// to ask the person for. It never gets a network: when a capability is
// granted, the runner carries out the one operation and hands back the
// result.

import { connect } from './keyweb-client.js';

const TAPE_KEY = 'peersync.tape';
const SYMBOL = { '+': '+', '-': '−', '*': '×', '/': '÷' };

const byId = (id) => document.getElementById(id);
const runner = connect();

// ---------------------------------------------------------------- the tape

function loadTape() {
  try {
    const stored = JSON.parse(localStorage.getItem(TAPE_KEY));
    return Array.isArray(stored) ? stored.filter((line) => typeof line === 'string').slice(0, 100) : [];
  } catch {
    return [];
  }
}

let tape = loadTape();

function saveTape() {
  try {
    localStorage.setItem(TAPE_KEY, JSON.stringify(tape));
  } catch {
    // Nothing to do: the tape lives until the page closes.
  }
}

function renderTape() {
  const list = byId('tape');
  list.replaceChildren();
  list.dataset.lines = String(tape.length);
  if (tape.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'hint';
    empty.textContent = 'Nothing yet. Work something out.';
    list.append(empty);
    return;
  }
  for (const line of tape) {
    const item = document.createElement('li');
    item.textContent = line;
    list.append(item);
  }
}

// ---------------------------------------------------------------- the calculator

const calc = { entry: '0', stored: null, operator: null, fresh: true };

function format(value) {
  if (!Number.isFinite(value)) return 'error';
  return String(Math.round(value * 1e10) / 1e10);
}

function apply(a, operator, b) {
  if (operator === '+') return a + b;
  if (operator === '-') return a - b;
  if (operator === '*') return a * b;
  return b === 0 ? NaN : a / b;
}

function press(key) {
  if (key === 'C') Object.assign(calc, { entry: '0', stored: null, operator: null, fresh: true });
  else if (/^[0-9]$/.test(key)) {
    calc.entry = calc.fresh || calc.entry === '0' ? key : (calc.entry + key).slice(0, 16);
    calc.fresh = false;
  } else if (key === '.') {
    if (calc.fresh) calc.entry = '0.';
    else if (!calc.entry.includes('.')) calc.entry += '.';
    calc.fresh = false;
  } else if (key in SYMBOL) {
    if (calc.operator && !calc.fresh) equals();
    calc.stored = Number(calc.entry);
    calc.operator = key;
    calc.fresh = true;
  } else if (key === '=') equals();
  byId('display').textContent = calc.entry;
}

function equals() {
  if (calc.operator === null || calc.stored === null) return;
  const b = Number(calc.entry);
  const result = format(apply(calc.stored, calc.operator, b));
  tape.unshift(`${format(calc.stored)} ${SYMBOL[calc.operator]} ${format(b)} = ${result}`);
  tape = tape.slice(0, 100);
  saveTape();
  renderTape();
  calc.entry = result === 'error' ? '0' : result;
  calc.stored = null;
  calc.operator = null;
  calc.fresh = true;
}

byId('keys').addEventListener('click', (event) => {
  const key = event.target.closest('[data-key]');
  if (key) press(key.dataset.key);
});

byId('tape-clear').addEventListener('click', () => {
  tape = [];
  saveTape();
  renderTape();
  say('info', 'Local tape cleared. If you synced it, you can pull it back from the relay.');
});

// ---------------------------------------------------------------- capabilities

function say(kind, text, code = '') {
  const list = byId('status');
  const item = document.createElement('li');
  item.className = kind;
  item.textContent = text;
  list.prepend(item);
  list.dataset.last = code;
  while (list.children.length > 8) list.lastElementChild.remove();
}

const EXPLAIN = {
  DENIED: 'You said no. Nothing was sent, and the app carries on in Tier 0.',
  CLOSED: 'The app was closed before you answered.',
  UNKNOWN_CAPABILITY: 'The runner does not broker any such capability, so you were never asked.',
  UNDECLARED_CAPABILITY: 'This app did not declare that capability in its signed descriptor, so you were never asked.',
  RELAY_UNREACHABLE: 'Granted, but the relay is unreachable: the network is down.',
  NO_RUNNER: 'There is no runner to ask.',
};

/**
 * Tries an operation. If the capability is not granted, asks for it, and
 * if the person grants it, tries once more.
 */
async function withCapability(capability, reason, args) {
  let outcome = await runner.invoke(capability, args);
  if (!outcome.ok && (outcome.error === 'CAPABILITY_NOT_GRANTED' || outcome.error === 'GRANT_EXPIRED')) {
    say('info', `${capability} is not granted. Asking you for it.`, 'ASKING');
    const answer = await runner.request(capability, reason);
    if (!answer.ok) {
      say('bad', `${capability}: ${answer.error}. ${EXPLAIN[answer.error] || ''}`, answer.error);
      return null;
    }
    say('ok', `${capability} granted ${answer.mode === 'once' ? 'for one use' : 'for five minutes'}.`, 'GRANTED');
    outcome = await runner.invoke(capability, args);
  }
  if (!outcome.ok) {
    say('bad', `${capability}: ${outcome.error}. ${EXPLAIN[outcome.error] || ''}`, outcome.error);
    return null;
  }
  return outcome.result;
}

byId('sync-push').addEventListener('click', async () => {
  const result = await withCapability('net:sync-relay', 'Back up your calculator tape so another device can pick it up.', { op: 'push', data: JSON.stringify({ tape }) });
  if (result) say('ok', `Synced ${tape.length} tape line${tape.length === 1 ? '' : 's'} to the relay: ${result.bytes} bytes, relay version ${result.version}.`, 'PUSHED');
});

byId('sync-pull').addEventListener('click', async () => {
  const result = await withCapability('net:sync-relay', 'Fetch the tape you synced earlier.', { op: 'pull' });
  if (!result) return;
  if (result.data === null) {
    say('info', 'The relay holds nothing for this key yet.', 'EMPTY');
    return;
  }
  try {
    const pulled = JSON.parse(result.data).tape;
    if (!Array.isArray(pulled)) throw new Error('not a tape');
    tape = pulled.filter((line) => typeof line === 'string').slice(0, 100);
    saveTape();
    renderTape();
    say('ok', `Pulled ${tape.length} tape line${tape.length === 1 ? '' : 's'} from the relay.`, 'PULLED');
  } catch {
    say('bad', 'The relay returned something that is not a tape.', 'BAD_DATA');
  }
});

byId('export').addEventListener('click', async () => {
  const result = await withCapability('storage:export', 'Save your tape as a text file.', { filename: 'peersync-tape.txt', text: `${tape.join('\n')}\n` });
  if (result) say('ok', `Exported ${result.filename}: ${result.bytes} bytes. The runner wrote the file, not this app.`, 'EXPORTED');
});

byId('unknown').addEventListener('click', async () => {
  const answer = await runner.request('net:anywhere', 'Let me talk to any server I like.');
  say(answer.ok ? 'bad' : 'ok', answer.ok ? 'net:anywhere was granted. That should never happen.' : `net:anywhere: ${answer.error}. ${EXPLAIN[answer.error] || ''}`, answer.ok ? 'GRANTED' : answer.error);
});

renderTape();
runner.context.then((context) => {
  if (!context.framed) byId('tier').textContent = 'Not running inside KeyWeb Runner, so there is nobody to ask for a capability.';
  document.documentElement.dataset.ready = 'true';
});
