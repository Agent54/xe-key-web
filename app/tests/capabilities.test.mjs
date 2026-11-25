// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Capability grants: declared, asked for, granted once or for five minutes.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { CAPABILITIES, GRANT_MODES, GrantBook, checkArguments } from '../runner/src/capabilities.js';
import { MAX_RELAY_BYTES, TIMED_GRANT_MS } from '../runner/src/config.js';

const APP = 'a'.repeat(56);
const OTHER = 'b'.repeat(56);
const DECLARED = ['net:sync-relay', 'storage:export'];

function bookAt() {
  const clock = { now: 1_000_000 };
  return { clock, book: new GrantBook({ now: () => clock.now }) };
}

describe('asking', () => {
  test('a capability must be known to the runner and declared by the app', () => {
    const { book } = bookAt();
    assert.deepEqual(book.screen('net:sync-relay', DECLARED), { ok: true });
    assert.deepEqual(book.screen('net:anywhere', DECLARED), { ok: false, code: 'UNKNOWN_CAPABILITY' });
    assert.deepEqual(book.screen('net:sync-relay', []), { ok: false, code: 'UNDECLARED_CAPABILITY' });
    assert.deepEqual(book.screen('net:sync-relay', null), { ok: false, code: 'UNDECLARED_CAPABILITY' });
    for (const odd of [undefined, null, 7, {}, 'constructor', 'toString', '__proto__']) assert.equal(book.screen(odd, DECLARED).code, 'UNKNOWN_CAPABILITY');
  });

  test('every capability says in plain words what it grants and what it does not', () => {
    for (const [name, info] of Object.entries(CAPABILITIES)) {
      assert.match(name, /^[a-z]+:[a-z-]+$/);
      assert.ok(info.title.length > 3 && info.grants.length > 20 && info.limits.length >= 2, name);
    }
    assert.deepEqual([...GRANT_MODES], ['once', 'timed']);
  });
});

describe('grants', () => {
  test('nothing is granted to begin with', () => {
    const { book } = bookAt();
    assert.deepEqual(book.check(APP, 'net:sync-relay'), { ok: false, code: 'CAPABILITY_NOT_GRANTED' });
    assert.deepEqual(book.use(APP, 'net:sync-relay'), { ok: false, code: 'CAPABILITY_NOT_GRANTED' });
    assert.deepEqual(book.list(), []);
  });

  test('"once" is good for exactly one operation', () => {
    const { book } = bookAt();
    const grant = book.grant(APP, 'net:sync-relay', 'once');
    assert.equal(grant.expires, null);
    assert.equal(book.check(APP, 'net:sync-relay').ok, true);
    assert.equal(book.check(APP, 'net:sync-relay').ok, true);
    assert.equal(book.use(APP, 'net:sync-relay').ok, true);
    assert.deepEqual(book.use(APP, 'net:sync-relay'), { ok: false, code: 'CAPABILITY_NOT_GRANTED' });
    assert.deepEqual(book.list(APP), []);
  });

  test('"timed" lasts five minutes and not a millisecond more', () => {
    const { book, clock } = bookAt();
    const grant = book.grant(APP, 'net:sync-relay', 'timed');
    assert.equal(grant.expires - grant.grantedAt, TIMED_GRANT_MS);
    assert.equal(TIMED_GRANT_MS, 5 * 60 * 1000);
    for (let i = 0; i < 5; i++) assert.equal(book.use(APP, 'net:sync-relay').ok, true);
    assert.equal(book.list(APP)[0].uses, 5);
    clock.now += TIMED_GRANT_MS - 1;
    assert.equal(book.use(APP, 'net:sync-relay').ok, true);
    clock.now += 1;
    assert.deepEqual(book.use(APP, 'net:sync-relay'), { ok: false, code: 'GRANT_EXPIRED' });
    assert.deepEqual(book.use(APP, 'net:sync-relay'), { ok: false, code: 'CAPABILITY_NOT_GRANTED' });
    assert.deepEqual(book.list(), []);
  });

  test('a grant is for one capability of one app', () => {
    const { book } = bookAt();
    book.grant(APP, 'net:sync-relay', 'timed');
    assert.equal(book.check(APP, 'storage:export').ok, false);
    assert.equal(book.check(OTHER, 'net:sync-relay').ok, false);
    book.grant(OTHER, 'storage:export', 'once');
    assert.equal(book.list().length, 2);
    assert.equal(book.list(APP).length, 1);
  });

  test('can be revoked, one at a time or all at once when the app closes', () => {
    const { book } = bookAt();
    book.grant(APP, 'net:sync-relay', 'timed');
    book.grant(APP, 'storage:export', 'timed');
    book.grant(OTHER, 'net:sync-relay', 'timed');
    assert.equal(book.revoke(APP, 'net:sync-relay'), true);
    assert.equal(book.revoke(APP, 'net:sync-relay'), false);
    assert.equal(book.check(APP, 'net:sync-relay').ok, false);
    book.revokeAll(APP);
    assert.deepEqual(book.list(APP), []);
    assert.equal(book.list(OTHER).length, 1);
  });

  test('cannot be made for an unknown capability or mode', () => {
    const { book } = bookAt();
    assert.throws(() => book.grant(APP, 'net:anywhere', 'once'), /unknown capability/);
    assert.throws(() => book.grant(APP, 'net:sync-relay', 'forever'), /unknown grant mode/);
  });
});

describe('operation arguments', () => {
  test('the relay takes a push of bounded text or a pull, and nothing else', () => {
    assert.deepEqual(checkArguments('net:sync-relay', { op: 'pull' }), { ok: true, op: 'pull' });
    assert.deepEqual(checkArguments('net:sync-relay', { op: 'push', data: 'tape' }), { ok: true, op: 'push', data: 'tape' });
    assert.equal(checkArguments('net:sync-relay', { op: 'push', data: 'x'.repeat(MAX_RELAY_BYTES) }).ok, true);
    assert.equal(checkArguments('net:sync-relay', { op: 'push', data: 'x'.repeat(MAX_RELAY_BYTES + 1) }).code, 'TOO_LARGE');
    assert.equal(checkArguments('net:sync-relay', { op: 'push', data: 'é'.repeat(MAX_RELAY_BYTES / 2 + 1) }).code, 'TOO_LARGE');
    for (const bad of [null, 'push', {}, { op: 'push' }, { op: 'push', data: 5 }, { op: 'delete' }, { op: 'push', data: 'x', url: 'elsewhere' }.url]) {
      assert.equal(checkArguments('net:sync-relay', bad).code, 'BAD_ARGUMENT');
    }
    // The app never chooses where the data goes: extra fields are not passed on.
    assert.deepEqual(Object.keys(checkArguments('net:sync-relay', { op: 'push', data: 'x', url: 'elsewhere', headers: {} })), ['ok', 'op', 'data']);
  });

  test('an export gets a plain file name whatever the app asked for', () => {
    assert.deepEqual(checkArguments('storage:export', { filename: 'tape.txt', text: 'x' }), { ok: true, filename: 'tape.txt', text: 'x' });
    assert.equal(checkArguments('storage:export', { filename: '../../.ssh/authorized_keys', text: 'x' }).filename, '_.._.ssh_authorized_keys');
    assert.equal(checkArguments('storage:export', { filename: '.bashrc', text: 'x' }).filename, 'bashrc');
    assert.equal(checkArguments('storage:export', { filename: 'a b\\c:d.txt', text: 'x' }).filename, 'a_b_c_d.txt');
    assert.equal(checkArguments('storage:export', { text: 'x' }).filename, 'export.txt');
    assert.equal(checkArguments('storage:export', { filename: 'x'.repeat(200), text: 'x' }).filename.length, 64);
    assert.equal(checkArguments('storage:export', { filename: 'a.txt' }).code, 'BAD_ARGUMENT');
    assert.equal(checkArguments('storage:export', { filename: 'a.txt', text: 'x'.repeat(1024 * 1024 + 1) }).code, 'BAD_ARGUMENT');
    assert.equal(checkArguments('net:anywhere', { op: 'pull' }).code, 'UNKNOWN_CAPABILITY');
  });
});
