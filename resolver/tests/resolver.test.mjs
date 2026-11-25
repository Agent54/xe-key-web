// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// End-to-end resolver behaviour (Spec §1.7.5-§1.7.8), using the REAL at /
// dht / nostr adapters over in-memory transports.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { KeyWebResolver, TrustStore, pinFor, LocalRail, bookEntry } from '../src/index.mjs';
import { createOfflineWorld, makePublisher, makeApp, makeSaidApp, simpleTombstone, testSeed } from '../src/fixtures.mjs';
import { signAppRecord, signPublisherDoc } from '../src/records.mjs';
import { rotate } from '../src/kel.mjs';
import { ed25519 } from '../src/crypto.mjs';
import { BOOK_TYPE } from '../src/rails/local.mjs';

function setup({ profile = 'K-SAID', appId = makeApp('cool-site').id, store = new TrustStore() } = {}) {
  const world = createOfflineWorld();
  const alice = makePublisher('alice', { profile });
  const publish = (apps, pub = alice) => {
    const records = { pdoc: pub.pdoc(), apps };
    world.publishEverywhere(pub, records);
    return records;
  };
  publish({ 'cool-site': alice.app('cool-site', appId) });
  const resolver = new KeyWebResolver({ rails: world.rails(), store });
  return { world, alice, appId, publish, store, resolver };
}

const AT = 'key-web://cool-site.alice.example/';
const atDown = (world) => ['dns', 'plc.test', 'pds-alice.test'].forEach((h) => world.down.add(h));

for (const profile of ['K-ED', 'K-SAID']) {
  test(`[${profile}] TOFU first contact, then known; only the key URL is ever opened`, async () => {
    const { resolver, appId, alice } = setup({ profile });
    const first = await resolver.resolve('key-web://cool-site.alice.example/notes/a?x=1#route:~:pin=' + pinFor(appId));
    assert.equal(first.ok, true, first.message);
    assert.equal(first.status, 'verified-pin');
    assert.equal(first.canonicalUrl, `key-web://${appId}.key/notes/a?x=1#route`);
    assert.equal(first.kPub, alice.id);
    assert.ok(!first.canonicalUrl.includes('alice'), 'the name never becomes the origin');
    assert.deepEqual(first.badges, ['AT', 'pinned', '3 rails agree']);
    assert.equal(first.share, `key-web://cool-site.alice.example/#:~:pin=${pinFor(appId)}`);
    assert.equal(first.display, 'cool-site · alice.example');

    const again = await resolver.resolve(AT);
    assert.equal(again.status, 'known');
    assert.equal(again.kApp, appId);
  });
}

test('TOFU without a pin binds with evidence "tofu"', async () => {
  const { resolver, store, alice, appId } = setup();
  const r = await resolver.resolve(AT);
  assert.equal(r.status, 'first-use');
  assert.equal(r.evidence, 'tofu');
  assert.equal(store.binding(alice.id, 'cool-site').app, appId);
});

test('pins: mismatch and short pins fail closed and bind nothing', async () => {
  const { resolver, store, alice } = setup();
  const wrong = await resolver.resolve(`${AT}#:~:pin=${pinFor(makeApp('evil').id)}`);
  assert.equal(wrong.ok, false);
  assert.equal(wrong.failClosed, true);
  assert.equal(wrong.code, 'PIN_MISMATCH');
  assert.equal(store.binding(alice.id, 'cool-site'), null);
  const short = await resolver.resolve(`${AT}#:~:pin=abcdefgh`);
  assert.deepEqual([short.code, short.failClosed], ['PIN_TOO_SHORT', true]);
});

test('cross-rail equivalence: every rail and label for K_app is ONE origin', async () => {
  const { resolver, alice, appId } = setup();
  const origin = `key-web://${appId}.key/`;
  assert.equal((await resolver.resolve(AT)).canonicalUrl, origin);
  for (const url of [
    'key-web://cool-site.alice.dht/',                    // short alias learned from the rail map
    `key-web://cool-site.${alice.pkarrKey}.dht/`,        // self-certifying PKARR key
    'key-web://cool-site.alice.example.dht/',            // full handle as alias
    'key-web://cool-site.alice.nostr/',
    `key-web://cool-site.${alice.npub}.nostr/`,          // self-certifying npub
    `key-web://cool-site.${alice.id}.key/`,              // self-certifying publisher key
  ]) {
    const r = await resolver.resolve(url);
    assert.equal(r.ok, true, `${url}: ${r.message}`);
    assert.equal(r.canonicalUrl, origin, url);
    assert.equal(r.kApp, appId, url);
  }
});

test('first-time users need a self-certifying label for dht/nostr', async () => {
  const { resolver, alice } = setup({ profile: 'K-ED' });
  const r = await resolver.resolve('key-web://cool-site.alice.dht/');
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'UNKNOWN_ALIAS', false]);
  assert.equal((await resolver.resolve(`key-web://cool-site.${alice.pkarrKey}.dht/`)).status, 'first-use');
  assert.equal((await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/`)).status, 'known');
});

test('K-SAID publisher documents do not fit PKARR: first contact needs another rail', async () => {
  const { resolver, alice } = setup({ profile: 'K-SAID' });
  const cold = await resolver.resolve(`key-web://cool-site.${alice.pkarrKey}.dht/`);
  assert.deepEqual([cold.ok, cold.code, cold.failClosed], [false, 'NOT_FOUND', false]);
  await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/`);
  const warm = await resolver.resolve(`key-web://cool-site.${alice.pkarrKey}.dht/`);
  assert.equal(warm.ok, true, 'the verified publisher document from nostr fills the gap');
});

test('every .at dependency down: .dht still opens live; .at opens from the cached binding', async () => {
  const { resolver, world, appId } = setup();
  await resolver.resolve(AT);
  atDown(world);
  const dht = await resolver.resolve('key-web://cool-site.alice.dht/');
  assert.equal(dht.ok, true);
  assert.equal(dht.kApp, appId);
  assert.notEqual(dht.status, 'cached');
  const at = await resolver.resolve(AT);
  assert.deepEqual([at.ok, at.status, at.kApp], [true, 'cached', appId]);
  assert.ok(at.badges.includes('offline: cached binding'));

  const fresh = new KeyWebResolver({ rails: world.rails(), store: new TrustStore() });
  const nothing = await fresh.resolve(AT);
  assert.deepEqual([nothing.ok, nothing.failClosed], [false, false]);
});

test('handle hijack: the handle now points at K_evil -> FAIL-CLOSED, data stays with K_app', async () => {
  const { resolver, world, store, alice, appId } = setup();
  await resolver.resolve(AT);
  const mallory = makePublisher('mallory', { profile: 'K-ED', handle: 'alice.example', rails: ['at'] });
  const evilApp = makeApp('evil').id;
  world.publishAt(mallory, { pdoc: mallory.pdoc(), apps: { 'cool-site': mallory.app('cool-site', evilApp) } });

  const r = await resolver.resolve(AT);
  assert.equal(r.ok, false);
  assert.equal(r.failClosed, true);
  assert.equal(r.code, 'HANDLE_HIJACK');
  assert.deepEqual(r.known, { pub: alice.id, app: appId });
  assert.deepEqual(r.offered, { pub: mallory.id, app: evilApp });
  assert.equal(r.defaultAction, 'open-known');
  assert.equal(store.binding(alice.id, 'cool-site').app, appId, 'binding untouched');
  assert.equal(store.publisherForAlias('at', 'alice.example'), alice.id, 'alias untouched');
  assert.equal((await resolver.resolve('key-web://cool-site.alice.dht/')).kApp, appId, 'other rails keep working');
});

test('handle hijack on first contact is caught by a pin', async () => {
  const { world, appId } = setup();
  const mallory = makePublisher('mallory', { profile: 'K-ED', handle: 'alice.example', rails: ['at'] });
  world.publishAt(mallory, { pdoc: mallory.pdoc(), apps: { 'cool-site': mallory.app('cool-site', makeApp('evil').id) } });
  const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() })
    .resolve(`${AT}#:~:pin=${pinFor(appId)}`);
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'PIN_MISMATCH', true]);
});

test('copied records served from an unlisted DID: HANDLE_NOT_LISTED', async () => {
  const { world, alice, appId } = setup();
  const copycat = makePublisher('copycat', { profile: 'K-ED', handle: 'copycat.example', rails: ['at'] });
  // The attacker republishes alice's genuine signed bytes under their own handle.
  world.publishAt(copycat, { pdoc: alice.pdoc(), apps: { 'cool-site': alice.app('cool-site', appId) } });
  const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() })
    .resolve('key-web://cool-site.copycat.example/');
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'HANDLE_NOT_LISTED', true]);
});

test('a DID that does not claim the handle back: HANDLE_NOT_CLAIMED', async () => {
  const world = createOfflineWorld();
  const pub = makePublisher('hank', { profile: 'K-ED', rails: ['at'] });
  world.publishAt(pub, { pdoc: pub.pdoc(), apps: { notes: pub.app('notes', makeApp('hank').id) } }, { claimHandle: false });
  const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() }).resolve('key-web://notes.hank.example/');
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'HANDLE_NOT_CLAIMED', true]);
});

test('valid K_pub record pointing at a NEW K_app without proof: KEY_MISMATCH', async () => {
  const { resolver, publish, alice, appId, store } = setup();
  await resolver.resolve(AT);
  const other = makeApp('other').id;
  publish({ 'cool-site': alice.app('cool-site', other, { seq: 2 }) });
  const r = await resolver.resolve(AT);
  assert.deepEqual([r.ok, r.code, r.failClosed, r.defaultAction], [false, 'KEY_MISMATCH', true, 'open-known']);
  assert.equal(r.known.app, appId);
  assert.equal(r.offered.app, other);
  assert.equal(store.binding(alice.id, 'cool-site').app, appId);
});

test('succession (K-SAID app): offered, never silent; moves only after confirmation', async () => {
  const oldApp = makeSaidApp('succession-old');
  const { resolver, publish, alice, store } = setup({ appId: oldApp.id });
  await resolver.resolve(AT);
  const next = makeApp('succession-new').id;
  publish({ 'cool-site': alice.app('cool-site', next, { seq: 2, succ: { from: oldApp.id, kel: oldApp.retireTo(next) } }) });

  const offered = await resolver.resolve(AT);
  assert.deepEqual([offered.ok, offered.code, offered.failClosed, offered.requiresConfirmation], [false, 'SUCCESSION_OFFERED', false, true]);
  assert.equal(store.binding(alice.id, 'cool-site').app, oldApp.id, 'still bound to the old key');

  const moved = await resolver.resolve(AT, { acceptSuccession: true });
  assert.deepEqual([moved.ok, moved.status, moved.kApp], [true, 'succession', next]);
  assert.equal(store.binding(alice.id, 'cool-site').app, next);
});

test('succession proofs must be real: wrong successor or replayed seq fail closed', async () => {
  const oldApp = makeSaidApp('succ-bad');
  const { resolver, publish, alice } = setup({ appId: oldApp.id });
  await resolver.resolve(AT);
  const next = makeApp('succ-bad-new').id;
  const elsewhere = makeApp('succ-bad-elsewhere').id;
  publish({ 'cool-site': alice.app('cool-site', next, { seq: 2, succ: { from: oldApp.id, kel: oldApp.retireTo(elsewhere) } }) });
  assert.equal((await resolver.resolve(AT)).code, 'KEY_MISMATCH');
  publish({ 'cool-site': alice.app('cool-site', next, { seq: 1, succ: { from: oldApp.id, kel: oldApp.retireTo(next) } }) });
  assert.equal((await resolver.resolve(AT)).code, 'RECORD_ROLLBACK');
});

test('succession (K-ED app): self-signed tomb is accepted after confirmation', async () => {
  const oldApp = makeApp('ked-old');
  const { resolver, publish, alice } = setup({ appId: oldApp.id });
  await resolver.resolve(AT);
  const next = makeApp('ked-new').id;
  publish({ 'cool-site': alice.app('cool-site', next, { seq: 2, succ: { from: oldApp.id, tomb: simpleTombstone(oldApp.keyPair, { successor: next }) } }) });
  assert.equal((await resolver.resolve(AT)).code, 'SUCCESSION_OFFERED');
  assert.equal((await resolver.resolve(AT, { acceptSuccession: true })).kApp, next);
});

test('rails disagree on first contact: refuse to bind; a pin decides', async () => {
  const world = createOfflineWorld();
  const alice = makePublisher('alice', { profile: 'K-ED' });
  const a = makeApp('disagree-a').id;
  const b = makeApp('disagree-b').id;
  const pdoc = alice.pdoc();
  world.publishAt(alice, { pdoc, apps: { 'cool-site': alice.app('cool-site', a) } });
  world.publishDht(alice, { pdoc, apps: { 'cool-site': alice.app('cool-site', a) } });
  world.publishNostr(alice, { pdoc, apps: { 'cool-site': alice.app('cool-site', b) } });

  const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() }).resolve(AT);
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'RAILS_DISAGREE', true]);
  assert.deepEqual(r.answers.map((x) => x.app).sort(), [a, b].sort());

  const store = new TrustStore();
  const pinned = await new KeyWebResolver({ rails: world.rails(), store }).resolve(`${AT}#:~:pin=${pinFor(a)}`);
  assert.equal(pinned.ok, true);
  assert.ok(pinned.badges.includes('⚠ rails disagree'));
  assert.equal(store.binding(alice.id, 'cool-site').contested, true);
});

test('KERI rotation: same K_pub after rotation; the rotated-out key is powerless', async () => {
  const { resolver, publish, alice, appId, world } = setup({ profile: 'K-SAID' });
  await resolver.resolve(AT);
  const stolen = alice.currentKey();
  alice.rotate();
  publish({ 'cool-site': alice.app('cool-site', appId, { seq: 2 }) });
  const after = await resolver.resolve(AT);
  assert.deepEqual([after.ok, after.status, after.kPub], [true, 'known', alice.id]);
  assert.ok(after.badges.includes('3 rails agree'));

  // The thief signs a fresh document + record with the stolen, rotated-out key.
  const forgedDoc = signPublisherDoc({ pub: alice.id, seq: 50, rails: alice.railMap(), kel: alice.kel }, [stolen]);
  const forgedRec = signAppRecord({ pub: alice.id, slug: 'cool-site', app: makeApp('thief').id, seq: 50 }, [stolen]);
  world.publishNostr(alice, { pdoc: forgedDoc, apps: { 'cool-site': forgedRec } });
  const r = await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/`);
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'BAD_SIGNATURE', true]);
  assert.equal(r.known.app, appId);
});

test('KERI duplicity: a forked KEL freezes the publisher (fail closed)', async () => {
  const { resolver, publish, alice, appId, world } = setup({ profile: 'K-SAID' });
  const icpOnly = alice.kel.slice(0, 1);
  const revealedNext = alice.nextKey();
  alice.rotate();
  publish({ 'cool-site': alice.app('cool-site', appId, { seq: 2 }) });
  await resolver.resolve(AT);

  // Someone holding the next key publishes a DIFFERENT event at sn 1.
  const forkKel = [...icpOnly, rotate(icpOnly, { revealed: [revealedNext], next: [ed25519.fromSeed(testSeed('fork'))] })];
  const forkDoc = signPublisherDoc({ pub: alice.id, seq: 60, rails: alice.railMap(), kel: forkKel }, [revealedNext]);
  const forkRec = signAppRecord({ pub: alice.id, slug: 'cool-site', app: makeApp('fork').id, seq: 60 }, [revealedNext]);
  world.publishNostr(alice, { pdoc: forkDoc, apps: { 'cool-site': forkRec } });
  const r = await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/`);
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'KEL_DUPLICITY', true]);
});

test('publisher key changed under a known petname: attribution suspended, origin unchanged', async () => {
  const app = makeApp('mom-recipes').id;
  const mom1 = makePublisher('mom1', { profile: 'K-ED', rails: [] });
  const mom2 = makePublisher('mom2', { profile: 'K-ED', rails: [] });
  const book = (pub) => ({ t: BOOK_TYPE, petnames: { mom: pub.id }, records: { [pub.id]: bookEntry(pub.pdoc(), { recipes: pub.app('recipes', app) }) } });
  const store = new TrustStore();
  const first = await new KeyWebResolver({ rails: { local: new LocalRail({ book: book(mom1) }) }, store }).resolve('key-web://recipes.mom.local/');
  assert.equal(first.status, 'first-use');
  assert.equal(first.share, `key-web://${app}.key/#:~:pin=${pinFor(app)}`, '.local is shared as a pinned key URL');
  const second = await new KeyWebResolver({ rails: { local: new LocalRail({ book: book(mom2) }) }, store }).resolve('key-web://recipes.mom.local/');
  assert.equal(second.ok, true);
  assert.equal(second.kApp, app);
  assert.equal(second.attributionSuspended, true);
  assert.ok(second.badges.includes('⚠ publisher key changed'));
  assert.equal(store.binding(mom1.id, 'recipes').app, app, 'binding stays with the original publisher');
});

test('tampered PKARR transport on first contact fails closed', async () => {
  const { world, alice } = setup({ profile: 'K-ED' });
  const url = `https://pkarr-relay.test/${alice.pkarrKey}`;
  const original = world.rawHttp.get(url);
  world.rawHttp.set(url, async () => {
    const res = await original();
    const body = new Uint8Array(await res.arrayBuffer());
    body[body.length - 1] ^= 1;
    return { ok: true, status: 200, arrayBuffer: async () => body.buffer };
  });
  const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() })
    .resolve(`key-web://cool-site.${alice.pkarrKey}.dht/`);
  assert.deepEqual([r.ok, r.code, r.failClosed], [false, 'TRANSPORT_INVALID', true]);
});

test('key URLs resolve with no lookup; bare IDs become <id>.key', async () => {
  const resolver = new KeyWebResolver({ rails: {} });
  const id = makeApp('direct').id;
  const r = await resolver.resolve(`key-web://${id}/x#:~:pin=${pinFor(id)}`);
  assert.deepEqual([r.ok, r.status, r.canonicalUrl, r.rewrittenFromBareId], [true, 'verified-pin', `key-web://${id}.key/x`, true]);
  const bad = await resolver.resolve(`key-web://${id}.key/#:~:pin=${pinFor(makeApp('nope').id)}`);
  assert.deepEqual([bad.ok, bad.code, bad.failClosed], [false, 'PIN_MISMATCH', true]);
  assert.equal((await resolver.resolve('https://example.org/')).code, 'BAD_URL');
});

test('trust store persists across restarts; hijack is still detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyweb-store-'));
  try {
    const file = path.join(dir, 'trust.json');
    const { world, appId } = setup({ store: new TrustStore({ file }) });
    await new KeyWebResolver({ rails: world.rails(), store: new TrustStore({ file }) }).resolve(AT);
    assert.equal((fs.statSync(file).mode & 0o777).toString(8), '600');

    const restarted = new KeyWebResolver({ rails: world.rails(), store: new TrustStore({ file }) });
    assert.equal((await restarted.resolve(AT)).status, 'known');
    const mallory = makePublisher('mallory', { profile: 'K-ED', handle: 'alice.example', rails: ['at'] });
    world.publishAt(mallory, { pdoc: mallory.pdoc(), apps: { 'cool-site': mallory.app('cool-site', makeApp('evil').id) } });
    const r = await new KeyWebResolver({ rails: world.rails(), store: new TrustStore({ file }) }).resolve(AT);
    assert.equal(r.code, 'HANDLE_HIJACK');
    assert.equal(r.known.app, appId);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('forget(app) removes bindings; the next contact is TOFU again', async () => {
  const { resolver, appId } = setup();
  await resolver.resolve(AT);
  resolver.forget(appId);
  assert.equal((await resolver.resolve(AT)).status, 'first-use');
});
