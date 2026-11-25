// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// LocalPad: notes and a sketchpad that live in this origin's own storage
// and nowhere else. It asks for no capability and makes no request. What it
// shows at the top is the point of the demo: the data it finds when it
// opens is the same whichever transport delivered its bundle, because the
// storage belongs to the signing key, not to a server.

import { connect } from './keyweb-client.js';

const STORAGE_KEY = 'localpad.v1';
const TRANSPORTS = [['http', 'HTTP mirror'], ['swarm', 'P2P swarm'], ['file', 'File drop'], ['paste', 'Pasted base64'], ['cache', 'Offline cache']];
const INK = '#f2b23a';

const byId = (id) => document.getElementById(id);
const runner = connect();

function load() {
  const empty = { notes: [], strokes: [], boots: {}, bootCount: 0 };
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (!stored || typeof stored !== 'object') return empty;
    return {
      notes: Array.isArray(stored.notes) ? stored.notes.filter((note) => note && typeof note.text === 'string') : [],
      strokes: Array.isArray(stored.strokes) ? stored.strokes.filter(Array.isArray) : [],
      boots: stored.boots && typeof stored.boots === 'object' ? stored.boots : {},
      bootCount: Number.isSafeInteger(stored.bootCount) ? stored.bootCount : 0,
    };
  } catch {
    return empty;
  }
}

const state = load();

function save() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    byId('proof').textContent = 'This origin cannot write to its storage, so nothing will be kept.';
    return false;
  }
}

/** A short fingerprint of the notes and the sketch, to compare by eye across boots. */
async function digest() {
  const bytes = new TextEncoder().encode(JSON.stringify([state.notes, state.strokes]));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...hash.subarray(0, 4)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------- notes

function renderNotes() {
  const list = byId('notes');
  list.replaceChildren();
  if (state.notes.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'hint';
    empty.textContent = 'No notes yet.';
    list.append(empty);
    return;
  }
  for (const note of state.notes) {
    const item = document.createElement('li');
    item.className = 'note';
    const body = document.createElement('div');
    body.className = 'note-body';
    body.textContent = note.text;
    const time = document.createElement('span');
    time.className = 'note-time';
    time.textContent = new Date(note.at).toLocaleString('en-GB');
    body.append(time);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'btn note-remove';
    remove.textContent = 'Delete';
    remove.addEventListener('click', () => {
      state.notes = state.notes.filter((candidate) => candidate !== note);
      save();
      renderNotes();
    });
    item.append(body, remove);
    list.append(item);
  }
}

byId('note-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const field = byId('note-text');
  const text = field.value.trim();
  if (!text) return;
  state.notes.unshift({ text: text.slice(0, 2000), at: Date.now() });
  state.notes = state.notes.slice(0, 200);
  save();
  field.value = '';
  renderNotes();
});

// ---------------------------------------------------------------- sketchpad

const canvas = byId('sketch');
const pen = canvas.getContext('2d');
let stroke = null;

function drawStroke(points) {
  if (points.length < 2) return;
  pen.beginPath();
  pen.moveTo(points[0] * canvas.width, points[1] * canvas.height);
  for (let i = 2; i < points.length; i += 2) pen.lineTo(points[i] * canvas.width, points[i + 1] * canvas.height);
  pen.stroke();
}

function renderSketch() {
  pen.clearRect(0, 0, canvas.width, canvas.height);
  pen.strokeStyle = INK;
  pen.lineWidth = 3;
  pen.lineCap = 'round';
  pen.lineJoin = 'round';
  for (const points of state.strokes) drawStroke(points);
  if (stroke) drawStroke(stroke);
  byId('sketch-info').textContent = `${state.strokes.length} stroke${state.strokes.length === 1 ? '' : 's'} saved`;
}

function pointOf(event) {
  const box = canvas.getBoundingClientRect();
  const clamp = (value) => Math.round(Math.min(1, Math.max(0, value)) * 1000) / 1000;
  return [clamp((event.clientX - box.left) / box.width), clamp((event.clientY - box.top) / box.height)];
}

canvas.addEventListener('pointerdown', (event) => {
  canvas.setPointerCapture(event.pointerId);
  stroke = pointOf(event);
});
canvas.addEventListener('pointermove', (event) => {
  if (!stroke || stroke.length >= 1200) return;
  stroke.push(...pointOf(event));
  renderSketch();
});
const endStroke = () => {
  if (!stroke) return;
  // A click with no movement is a dot.
  if (stroke.length === 2) stroke.push(stroke[0] + 0.002, stroke[1] + 0.002);
  state.strokes.push(stroke);
  state.strokes = state.strokes.slice(-400);
  stroke = null;
  save();
  renderSketch();
};
canvas.addEventListener('pointerup', endStroke);
canvas.addEventListener('pointercancel', endStroke);

byId('sketch-clear').addEventListener('click', () => {
  state.strokes = [];
  save();
  renderSketch();
});

// ---------------------------------------------------------------- the proof

async function start() {
  byId('origin').textContent = location.origin;
  const found = `${state.notes.length} note${state.notes.length === 1 ? '' : 's'}, ${state.strokes.length} sketch stroke${state.strokes.length === 1 ? '' : 's'}, state digest ${await digest()}`;
  byId('found').textContent = found;
  byId('found').dataset.notes = String(state.notes.length);
  renderNotes();
  renderSketch();

  const context = await runner.context;
  const transport = TRANSPORTS.some(([key]) => key === context.transport) ? context.transport : null;
  state.bootCount += 1;
  if (transport) state.boots[transport] = (Number(state.boots[transport]) || 0) + 1;
  save();

  const used = TRANSPORTS.filter(([key]) => Number(state.boots[key]) > 0);
  const label = transport ? TRANSPORTS.find(([key]) => key === transport)[1] : 'an unknown transport';
  byId('proof').textContent = state.bootCount === 1
    ? `First time this origin has been opened. The bundle arrived by ${label}.`
    : `Opened ${state.bootCount} times, through ${used.length} different transport${used.length === 1 ? '' : 's'}. This time: ${label}. The notes and the sketch below were here before the bundle arrived.`;
  byId('proof').dataset.transport = transport || '';
  byId('proof').dataset.boots = String(state.bootCount);
  const chips = byId('transports');
  chips.replaceChildren();
  for (const [key, name] of TRANSPORTS) {
    const count = Number(state.boots[key]) || 0;
    const chip = document.createElement('li');
    chip.className = count > 0 ? 'chip chip-on' : 'chip';
    chip.textContent = count > 0 ? `${name} ×${count}` : name;
    chips.append(chip);
  }
}

start();
