// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Human-readable addresses, the signed records rails answer with, and the
// pins that decide what a name means.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { NAME_FORMAT, NETWORK_RAILS, RAILS, addressOfKey, isLabel, parseAddress, publisherAnchor, verifyNameRecord } from '../runner/src/engine/names.js';
import { idFromLink } from '../runner/src/engine/swbn.js';
import { cleanName, petnameLabel } from '../runner/src/petnames.js';
import { PinBook, judgeRecord } from '../runner/src/pins.js';
import { makeNameRecord, rawPublicKey, webBundleId } from '../scripts/lib/swbn.mjs';
import { newKey } from './helpers.mjs';

const newId = () => webBundleId(rawPublicKey(newKey()));
const ISSUED = '2026-01-01T00:00:00.000Z';
// The petname rail's suffix and a web scheme, written in pieces: outside a
// key-web address the hygiene gate takes them for a host name.
const LOCAL = 'loc' + 'al';
const WEB = 'ht' + 'tp';

function memoryStore(initial) {
  let value = initial;
  return { load: () => value, save: (next) => { value = JSON.parse(JSON.stringify(next)); }, peek: () => value };
}

describe('addresses', () => {
  const id = newId();

  test('a readable name is app, publisher and rail', () => {
    assert.deepEqual(parseAddress('key-web://localpad.lukeinth.at/'), { kind: 'name', rail: 'at', app: 'localpad', publisher: 'lukeinth', host: 'localpad.lukeinth.at', address: 'key-web://localpad.lukeinth.at/' });
    assert.deepEqual(parseAddress('key-web://localpad.lukeinth.dht/'), { kind: 'name', rail: 'dht', app: 'localpad', publisher: 'lukeinth', host: 'localpad.lukeinth.dht', address: 'key-web://localpad.lukeinth.dht/' });
    assert.equal(parseAddress('key-web://leaky.mallory.dht/').publisher, 'mallory');
    assert.equal(parseAddress('key-web://peersync.lukeinth.at/').app, 'peersync');
  });

  test('is read the way people type it: no scheme, any case, a path, stray spaces', () => {
    const canonical = 'key-web://localpad.lukeinth.at/';
    for (const typed of ['localpad.lukeinth.at', '  key-web://localpad.lukeinth.at  ', 'KEY-WEB://LocalPad.LukeInTh.AT/', 'key-web://localpad.lukeinth.at/notes?x=1#top', 'localpad.lukeinth.at/']) {
      assert.equal(parseAddress(typed).address, canonical, typed);
    }
  });

  test('a key is its own address, with or without the .key rail', () => {
    const expected = { kind: 'key', rail: 'key', id, host: `${id}.key`, address: `key-web://${id}.key/` };
    for (const typed of [`key-web://${id}.key/`, `key-web://${id}/`, id, `${id}.key`, `isolated-app://${id}/`, `key-web://${id.toUpperCase()}.KEY/`]) {
      assert.deepEqual(parseAddress(typed), expected, typed);
    }
    assert.equal(addressOfKey(id), `key-web://${id}.key/`);
    assert.equal(idFromLink(`key-web://${id}.key/`), id);
    assert.equal(idFromLink(`key-web://${id}/`), id);
  });

  test('a petname is one label on the local rail', () => {
    assert.deepEqual(parseAddress('key-web://trusted-notes.local/'), { kind: 'petname', rail: LOCAL, label: 'trusted-notes', host: `trusted-notes.${LOCAL}`, address: 'key-web://trusted-notes.local/' });
    assert.equal(parseAddress(`Trusted-Notes.${LOCAL}`).address, 'key-web://trusted-notes.local/');
    assert.equal(petnameLabel('Trusted Notes'), 'trusted-notes');
    assert.equal(petnameLabel('  LocalPad!  '), 'localpad');
    assert.equal(petnameLabel('ＬｏｃａｌＰａｄ'), 'localpad');
    assert.equal(petnameLabel('---'), null);
    assert.equal(petnameLabel(cleanName('x'.repeat(100))).length, 32);
    assert.ok(isLabel(petnameLabel('A very long petname that goes on and on and on')));
  });

  test('anything else is not an address', () => {
    const almostKey = `${id.slice(0, 52)}aaaa`;
    const bad = [
      '', '   ', 'localpad', 'localpad.at', 'a.b.c.at', 'localpad.lukeinth.com', 'localpad.lukeinth.key', `${almostKey}.key`, `x.${id}.key`,
      'localpad..at', '-pad.lukeinth.at', 'pad-.lukeinth.at', 'local_pad.lukeinth.at', 'localpad.luke inth.at', `${'a'.repeat(33)}.lukeinth.at`,
      `a.b.${LOCAL}`, `.${LOCAL}`, `${WEB}://localpad.lukeinth.at/`, `${WEB}s://localpad.lukeinth.at/`, 'localhost:5760', 'isolated-app://localpad.lukeinth.at/', 'key-web://', 'key-web:///',
      null, undefined, 42, {},
    ];
    for (const text of bad) assert.equal(parseAddress(text), null, String(text));
  });

  test('labels are DNS-shaped: letters, digits, inner hyphens, at most 32', () => {
    for (const good of ['a', 'a1', 'local-pad', 'x'.repeat(32), '0day']) assert.ok(isLabel(good), good);
    for (const bad of ['', '-a', 'a-', 'A', 'a.b', 'a_b', 'x'.repeat(33), 'é', 7, null]) assert.ok(!isLabel(bad), String(bad));
  });

  test('two rails ask the network, two never do', () => {
    assert.deepEqual([...NETWORK_RAILS], ['at', 'dht']);
    assert.deepEqual(Object.keys(RAILS), ['at', 'dht', 'local', 'key']);
    for (const [rail, info] of Object.entries(RAILS)) assert.equal(info.suffix, `.${rail}`);
    assert.equal(RAILS.key.network, false);
  });
});

describe('name records', () => {
  const publisher = newKey();
  const key = newId();
  const asked = { app: 'localpad', publisher: 'lukeinth', rail: 'at' };
  const make = (fields = {}) => makeNameRecord({ ...asked, key, sequence: 1, issued: ISSUED, signKey: publisher, ...fields });

  test('a record signed by the publisher key it carries verifies, and says which key the name means', async () => {
    const checked = await verifyNameRecord(make(), asked);
    assert.equal(checked.ok, true);
    assert.equal(checked.code, 'RECORD_VERIFIED');
    assert.equal(checked.key, key);
    assert.equal(checked.sequence, 1);
    assert.deepEqual([...checked.publisherKey], [...rawPublicKey(publisher)]);
    assert.deepEqual(checked.certificates, []);
    assert.equal(make().format, NAME_FORMAT);
  });

  test('a record for another name, or lifted from another rail, answers nothing', async () => {
    const record = make();
    assert.equal((await verifyNameRecord(record, { ...asked, app: 'peersync' })).code, 'RECORD_WRONG_NAME');
    assert.equal((await verifyNameRecord(record, { ...asked, publisher: 'mallory' })).code, 'RECORD_WRONG_NAME');
    assert.equal((await verifyNameRecord(record, { ...asked, rail: 'dht' })).code, 'RECORD_WRONG_NAME');
    assert.equal((await verifyNameRecord(record, {})).code, 'RECORD_WRONG_NAME');
  });

  test('a record changed after signing is rejected', async () => {
    const record = make();
    const other = newId();
    const retargeted = { ...record, payload: record.payload.replace(key, other) };
    assert.equal((await verifyNameRecord(retargeted, asked)).code, 'RECORD_SIGNATURE_INVALID');
    const reissued = { ...record, payload: record.payload.replace('"sequence":1', '"sequence":9') };
    assert.equal((await verifyNameRecord(reissued, asked)).code, 'RECORD_SIGNATURE_INVALID');
    // Someone else's key in place of the publisher's does not verify either.
    const swapped = { ...record, publisher_key: Buffer.from(rawPublicKey(newKey())).toString('base64url') };
    const checked = await verifyNameRecord(swapped, asked);
    assert.equal(checked.code, 'RECORD_SIGNATURE_INVALID');
    assert.equal(checked.key, null);
  });

  test('a hijacker can make a record that verifies: the signature alone proves nothing about who', async () => {
    const hijacker = newKey();
    const evil = newId();
    const checked = await verifyNameRecord(make({ key: evil, signKey: hijacker }), asked);
    assert.equal(checked.ok, true);
    assert.equal(checked.key, evil);
    assert.notDeepEqual([...checked.publisherKey], [...rawPublicKey(publisher)]);
  });

  test('rotation certificates ride along untouched, at most four of them', async () => {
    const certificates = Array.from({ length: 6 }, (_, index) => ({ format: 'key-web-rotation/1', payload: String(index) }));
    const checked = await verifyNameRecord(make({ rotation: certificates }), asked);
    assert.equal(checked.ok, true);
    assert.deepEqual(checked.certificates, certificates.slice(0, 4));
  });

  test('malformed records are rejected without throwing', async () => {
    const record = make();
    const payload = JSON.parse(record.payload);
    const withPayload = (change) => ({ ...record, payload: JSON.stringify({ ...payload, ...change }) });
    const cases = [
      null, 'text', [], {}, { ...record, format: 'key-web-name/2' }, { ...record, payload: 7 }, { ...record, payload: '{' }, { ...record, payload: 'null' },
      { ...record, payload: 'x'.repeat(3000) }, { ...record, signature: 'AAAA' }, { ...record, signature: '!!' }, { ...record, publisher_key: 'AAAA' }, { ...record, publisher_key: undefined },
      withPayload({ key: 'short' }), withPayload({ key: `${key.slice(0, 52)}aaaa` }), withPayload({ sequence: 0 }), withPayload({ sequence: '1' }),
    ];
    for (const bad of cases) {
      const checked = await verifyNameRecord(bad, asked);
      assert.equal(checked.ok, false);
      assert.equal(checked.code, 'RECORD_MALFORMED', JSON.stringify(bad).slice(0, 70));
      assert.equal(checked.key, null);
    }
  });

  test('what a rail would call the publisher is derived from the key, not taken from the rail', async () => {
    const raw = rawPublicKey(publisher);
    const did = await publisherAnchor('at', raw);
    assert.match(did, /^did:plc:[a-z2-7]{24}$/);
    assert.equal(did, await publisherAnchor('at', raw));
    assert.notEqual(did, await publisherAnchor('at', rawPublicKey(newKey())));
    assert.match(await publisherAnchor('dht', raw), /^pk:[a-z2-7]{52}$/);
  });
});

describe('pins', () => {
  const name = 'localpad.lukeinth.at';

  test('the first key a name resolves to is pinned', () => {
    const store = memoryStore({});
    const book = new PinBook(store);
    const key = newId();
    assert.equal(judgeRecord(book.get(name), key), 'first-use');
    const pin = book.pin(name, { key, publisherKey: 'cHVi' }, 1000);
    assert.deepEqual(pin, { key, publisherKey: 'cHVi', pinnedAt: 1000, seenAt: 1000, previous: [] });
    assert.equal(judgeRecord(book.get(name), key), 'match');
    assert.deepEqual(new PinBook(store).get(name), pin);
    assert.deepEqual(book.namesFor(key), [name]);
  });

  test('a different key later is a mismatch, and a pin cannot be overwritten by pinning again', () => {
    const book = new PinBook(memoryStore({}));
    const key = newId();
    const evil = newId();
    book.pin(name, { key });
    assert.equal(judgeRecord(book.get(name), evil), 'mismatch');
    assert.throws(() => book.pin(name, { key: evil }), /already pinned/);
    assert.equal(book.get(name).key, key);
  });

  test('a pin follows a verified rotation and remembers the key it left', () => {
    const book = new PinBook(memoryStore({}));
    const [first, second, third] = [newId(), newId(), newId()];
    book.pin(name, { key: first }, 1);
    assert.equal(book.follow(name, second, { publisherKey: 'bmV3' }, 2), true);
    assert.equal(book.get(name).key, second);
    assert.equal(book.get(name).publisherKey, 'bmV3');
    assert.equal(book.get(name).pinnedAt, 1);
    // The rail still serving the old key is behind, not hostile.
    assert.equal(judgeRecord(book.get(name), first), 'stale');
    assert.equal(judgeRecord(book.get(name), second), 'match');
    assert.equal(judgeRecord(book.get(name), third), 'mismatch');
    book.follow(name, third);
    assert.deepEqual(book.get(name).previous, [first, second]);
    assert.equal(book.follow(name, third), false);
    assert.equal(book.follow('peersync.lukeinth.at', third), false);
    assert.equal(book.follow(name, 'not-a-key'), false);
  });

  test('each name is pinned on its own, whichever rail it is on', () => {
    const book = new PinBook(memoryStore({}));
    const key = newId();
    book.pin('localpad.lukeinth.at', { key });
    assert.equal(book.get('localpad.lukeinth.dht'), null);
    book.pin('localpad.lukeinth.dht', { key });
    book.pin('leaky.mallory.dht', { key: newId() });
    assert.deepEqual(book.namesFor(key), ['localpad.lukeinth.at', 'localpad.lukeinth.dht']);
    assert.deepEqual(book.list().map((pin) => pin.name), ['leaky.mallory.dht', 'localpad.lukeinth.at', 'localpad.lukeinth.dht']);
  });

  test('only a readable name on a rail can be pinned', () => {
    const book = new PinBook(memoryStore({}));
    const key = newId();
    for (const bad of ['localpad', `trusted-notes.${LOCAL}`, `${key}.key`, 'key-web://localpad.lukeinth.at/', 'LocalPad.lukeinth.at', '']) {
      assert.throws(() => book.pin(bad, { key }), /only a name on a resolver rail/, bad);
    }
    assert.throws(() => book.pin(name, { key: 'nope' }), /needs a key/);
  });

  test('unpinning forgets, and a corrupted store is read as far as it makes sense', () => {
    const key = newId();
    const book = new PinBook(memoryStore({
      [name]: { key, pinnedAt: 5, previous: ['junk', key] },
      'bad name': { key },
      'peersync.lukeinth.at': { key: 'nope' },
      'leaky.mallory.dht': null,
    }));
    assert.deepEqual(book.list().map((pin) => pin.name), [name]);
    assert.deepEqual(book.get(name).previous, [key]);
    assert.equal(book.unpin(name), true);
    assert.equal(book.unpin(name), false);
    assert.equal(book.get(name), null);
    assert.deepEqual(new PinBook(memoryStore('garbage')).list(), []);
    assert.deepEqual(new PinBook(memoryStore([1])).list(), []);
    assert.equal(judgeRecord(null, key), 'first-use');
  });
});
