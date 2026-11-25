// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The petname book and the record of accepted key rotations.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { PetnameBook, RotationBook, cleanName, nameKey } from '../runner/src/petnames.js';
import { rawPublicKey, webBundleId } from '../scripts/lib/swbn.mjs';
import { newKey } from './helpers.mjs';

const newId = () => webBundleId(rawPublicKey(newKey()));

function memoryStore(initial) {
  let value = initial;
  return { load: () => value, save: (next) => { value = JSON.parse(JSON.stringify(next)); }, peek: () => value };
}

describe('names', () => {
  test('are compared without case, spacing or punctuation', () => {
    for (const same of ['LocalPad', 'localpad', 'Local Pad', ' local-pad ', 'LOCAL_PAD', 'Local​Pad', 'ＬｏｃａｌＰａｄ']) assert.equal(nameKey(same), 'localpad', same);
    assert.notEqual(nameKey('LocalPad'), nameKey('LocalPad2'));
    assert.equal(nameKey('   '), '');
    assert.equal(nameKey('!!!'), '');
    assert.equal(nameKey(null), '');
  });

  test('are shown trimmed, single-spaced, without control or direction-override characters', () => {
    assert.equal(cleanName('  Trusted   Notes \n'), 'Trusted Notes');
    assert.equal(cleanName('Pad‮daPlacoL'), 'PaddaPlacoL');
    assert.equal(cleanName('x'.repeat(100)).length, 40);
    assert.equal(cleanName(42), '');
  });
});

describe('the petname book', () => {
  test('binds a name to a key and remembers it', () => {
    const store = memoryStore([]);
    const book = new PetnameBook(store);
    const id = newId();
    const result = book.bind('  Trusted  Notes ', id, 123);
    assert.deepEqual(result, { ok: true, entry: { name: 'Trusted Notes', id, boundAt: 123, note: '' } });
    assert.equal(book.nameFor(id), 'Trusted Notes');
    assert.equal(book.entryForName('trusted notes').id, id);
    assert.equal(new PetnameBook(store).nameFor(id), 'Trusted Notes');
  });

  test('refuses a name that already belongs to a different key, however it is spelled', () => {
    const book = new PetnameBook(memoryStore([]));
    const real = newId();
    const fake = newId();
    book.bind('LocalPad', real);
    for (const disguise of ['LocalPad', 'localpad', 'Local Pad', 'LOCAL-PAD', 'ＬｏｃａｌＰａｄ']) {
      const result = book.bind(disguise, fake);
      assert.equal(result.ok, false, disguise);
      assert.equal(result.code, 'COLLISION');
      assert.equal(result.existing.id, real);
    }
    assert.equal(book.nameFor(fake), null);
    assert.equal(book.nameFor(real), 'LocalPad');
    assert.equal(book.list().length, 1);
  });

  test('renames a key that already has a petname, and frees the old name', () => {
    const book = new PetnameBook(memoryStore([]));
    const id = newId();
    book.bind('Notes', id);
    assert.equal(book.bind('Trusted Notes', id).ok, true);
    assert.equal(book.list().length, 1);
    assert.equal(book.entryForName('Notes'), null);
    assert.equal(book.bind('Notes', newId()).ok, true);
  });

  test('refuses empty names and things that are not key IDs', () => {
    const book = new PetnameBook(memoryStore([]));
    assert.equal(book.bind('', newId()).code, 'EMPTY_NAME');
    assert.equal(book.bind(' -- ', newId()).code, 'EMPTY_NAME');
    assert.equal(book.bind('Notes', 'not-a-key').code, 'BAD_KEY');
    assert.equal(book.bind('Notes', `${'a'.repeat(52)}aaaa`).code, 'BAD_KEY');
    assert.equal(book.list().length, 0);
  });

  test('judges a bundle by its key, never by the name it gives itself', () => {
    const book = new PetnameBook(memoryStore([]));
    const real = newId();
    const fake = newId();
    assert.deepEqual(book.judge('LocalPad', real), { status: 'unnamed', name: 'LocalPad' });
    book.bind('LocalPad', real);
    assert.deepEqual(book.judge('LocalPad', real), { status: 'petname', name: 'LocalPad' });
    // The real key is shown by the petname even if its bundle renames itself.
    assert.deepEqual(book.judge('Totally Different', real), { status: 'petname', name: 'LocalPad' });
    assert.deepEqual(book.judge('local pad', fake), { status: 'impostor', name: 'local pad', boundTo: real, petname: 'LocalPad' });
    assert.deepEqual(book.judge('Something Else', fake), { status: 'unnamed', name: 'Something Else' });
    assert.deepEqual(book.judge(null, fake), { status: 'unnamed', name: '' });
  });

  test('unbinds, and survives a corrupted store', () => {
    const id = newId();
    const book = new PetnameBook(memoryStore([{ name: 'Good', id }, { name: 'Bad', id: 'nope' }, null, { name: '', id: newId() }, 'junk']));
    assert.deepEqual(book.list().map((entry) => entry.name), ['Good']);
    assert.equal(book.unbind(id), true);
    assert.equal(book.unbind(id), false);
    assert.deepEqual(new PetnameBook(memoryStore('garbage')).list(), []);
    assert.deepEqual(new PetnameBook(memoryStore(null)).list(), []);
  });

  test('a petname follows its origin to the rotated key', () => {
    const book = new PetnameBook(memoryStore([]));
    const before = newId();
    const after = newId();
    book.bind('LocalPad', before);
    assert.equal(book.follow(before, after, 'followed key rotation 1'), true);
    assert.equal(book.nameFor(before), null);
    assert.equal(book.nameFor(after), 'LocalPad');
    assert.equal(book.list()[0].note, 'followed key rotation 1');
    assert.equal(book.follow(newId(), newId(), 'x'), false);
    assert.equal(book.follow(after, 'not-a-key', 'x'), false);
  });
});

describe('the rotation book', () => {
  test('follows accepted rotations to the current key', () => {
    const store = memoryStore({});
    const book = new RotationBook(store);
    const [a, b, c] = [newId(), newId(), newId()];
    assert.deepEqual(book.resolve(a), { id: a, hops: [] });
    assert.equal(book.sequenceFor(a), 0);
    book.accept(a, { to: b, sequence: 1, certificate: { any: 'thing' }, committedDigest: 'sha256:x' }, 5);
    assert.deepEqual(book.resolve(a), { id: b, hops: [{ from: a, to: b, sequence: 1 }] });
    assert.deepEqual(book.resolve(b), { id: b, hops: [] });
    book.accept(b, { to: c, sequence: 2, certificate: {}, committedDigest: 'sha256:y' });
    assert.equal(book.resolve(a).id, c);
    assert.equal(book.resolve(a).hops.length, 2);
    assert.equal(new RotationBook(store).resolve(a).id, c);
  });

  test('gives the sequence the next rotation must follow', () => {
    const book = new RotationBook(memoryStore({}));
    const [a, b] = [newId(), newId()];
    book.accept(a, { to: b, sequence: 1, certificate: {}, committedDigest: 'sha256:x' });
    // The same certificate again would be sequence 1 after sequence 1: a replay.
    assert.equal(book.sequenceFor(a), 1);
    // The new key's first rotation is sequence 2.
    assert.equal(book.sequenceFor(b), 1);
    assert.equal(book.sequenceFor(newId()), 0);
  });

  test('cannot be sent round in circles, and survives a corrupted store', () => {
    const [a, b] = [newId(), newId()];
    const book = new RotationBook(memoryStore({ [a]: { to: b, sequence: 1 }, [b]: { to: a, sequence: 2 }, junk: { to: a, sequence: 1 }, [newId()]: { to: 'nope', sequence: 1 }, [newId()]: null }));
    assert.equal(Object.keys(book.records).length, 2);
    assert.equal(book.resolve(a).id, b);
    assert.equal(book.resolve(a).hops.length, 1);
    assert.deepEqual(new RotationBook(memoryStore([1, 2])).records, {});
    book.reset();
    assert.deepEqual(book.resolve(a), { id: a, hops: [] });
  });
});
