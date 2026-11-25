// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// Rail adapters and their wire parsers, driven offline.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAtprotoTxt, parseWellKnownAtprotoDid, parseDidDocument, parseGetRecordResponse, didDocumentUrl, validateDid, AtRail, recordValue,
} from '../src/rails/at.mjs';
import { encodePacket, decodePacket } from '../src/rails/dns.mjs';
import { buildKwPacket, signPkarrPacket, parseSignedPacket, extractKwRecords, parsePkarrKey, DhtRail, PKARR_MAX_PACKET } from '../src/rails/dht.mjs';
import { eventId, verifyEvent, signEvent, kwEvent, pickEvent, npubToHex, hexToNpub, parseNip05, NostrRail, D_PUBLISHER, dTagForApp } from '../src/rails/nostr.mjs';
import { LocalRail, parsePublisherBook, bookEntry, BOOK_TYPE } from '../src/rails/local.mjs';
import { KeyRail } from '../src/rails/key.mjs';
import { railListed } from '../src/rails/common.mjs';
import { TrustStore } from '../src/store.mjs';
import { createOfflineWorld, makePublisher, makeApp, testSeed } from '../src/fixtures.mjs';
import { ed25519 } from '../src/crypto.mjs';

const DID = 'did:plc:abcdefghijklmnopqrstuvwx';

// --- at --------------------------------------------------------------------------

test('at: _atproto TXT parsing', () => {
  assert.equal(parseAtprotoTxt([['did=', DID]]), DID, 'TXT chunks are joined');
  assert.equal(parseAtprotoTxt([['v=spf1 -all'], [`did=${DID}`], [`did=${DID}`]]), DID);
  assert.throws(() => parseAtprotoTxt([['did=did:plc:abcdefghijklmnopqrstuvwx'], ['did=did:plc:bbbbbbbbbbbbbbbbbbbbbbbb']]), { code: 'TRANSPORT_INVALID' });
  assert.throws(() => parseAtprotoTxt([['hello']]), { code: 'NOT_FOUND' });
  assert.throws(() => parseAtprotoTxt([['did=did:key:z6Mk']]), { code: 'TRANSPORT_INVALID' });
});

test('at: /.well-known/atproto-did and DID validation', () => {
  assert.equal(parseWellKnownAtprotoDid(`${DID}\n`), DID);
  assert.equal(validateDid('did:web:alice.example'), 'did:web:alice.example');
  assert.throws(() => parseWellKnownAtprotoDid('<html>'), { code: 'TRANSPORT_INVALID' });
  assert.equal(didDocumentUrl(DID, 'https://plc.test/'), `https://plc.test/${DID}`);
  assert.equal(didDocumentUrl('did:web:alice.example', 'https://plc.test'), 'https://alice.example/.well-known/did.json');
});

test('at: DID document must claim the handle back and name an https PDS', () => {
  const doc = {
    id: DID,
    alsoKnownAs: ['at://alice.example'],
    service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://pds.test' }],
  };
  assert.deepEqual(parseDidDocument(doc, DID, 'alice.example'), { did: DID, pds: 'https://pds.test' });
  assert.throws(() => parseDidDocument({ ...doc, alsoKnownAs: ['at://mallory.example'] }, DID, 'alice.example'), { code: 'HANDLE_NOT_CLAIMED' });
  assert.throws(() => parseDidDocument({ ...doc, id: 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb' }, DID, 'alice.example'), { code: 'TRANSPORT_INVALID' });
  assert.throws(() => parseDidDocument({ ...doc, service: [{ ...doc.service[0], serviceEndpoint: 'http://pds.test' }] }, DID, 'alice.example'), { code: 'TRANSPORT_INVALID' });
});

test('at: getRecord responses carry the exact signed bytes', () => {
  const bytes = Uint8Array.of(1, 2, 3, 250);
  const collection = 'org.example.keyweb.app';
  const json = { uri: `at://${DID}/${collection}/cool-site`, value: recordValue(collection, bytes) };
  assert.deepEqual(parseGetRecordResponse(json, { did: DID, collection, rkey: 'cool-site' }), bytes);
  assert.throws(() => parseGetRecordResponse(json, { did: DID, collection, rkey: 'other' }), { code: 'TRANSPORT_INVALID' });
  assert.throws(() => parseGetRecordResponse({ ...json, value: { $type: collection } }, { did: DID, collection, rkey: 'cool-site' }), { code: 'TRANSPORT_INVALID' });
});

test('at: AtRail resolves handle -> DID -> PDS -> records, with HTTPS fallback', async () => {
  const world = createOfflineWorld();
  const pub = makePublisher('carol', { profile: 'K-ED' });
  const app = makeApp('carol-app');
  const records = { pdoc: pub.pdoc(), apps: { notes: pub.app('notes', app.id) } };
  world.publishAt(pub, records);
  const rail = world.rails().at;
  const got = await rail.resolve({ publisher: 'carol.example', slug: 'notes' });
  assert.equal(got.railId, pub.did);
  assert.deepEqual(got.rec, records.apps.notes);

  // No TXT record: fall back to https://<handle>/.well-known/atproto-did.
  world.rawTxt.clear();
  world.rawHttp.set('https://carol.example/.well-known/atproto-did', () => ({ ok: true, status: 200, text: async () => pub.did }));
  assert.equal((await rail.resolve({ publisher: 'carol.example', slug: 'notes' })).railId, pub.did);
  await assert.rejects(rail.resolve({ publisher: 'not a handle', slug: 'notes' }), { code: 'BAD_INPUT' });
  await assert.rejects(new AtRail({ fetch: world.fetch, resolveTxt: world.resolveTxt, plcDirectory: world.plcDirectory })
    .resolve({ publisher: 'nobody.example', slug: 'notes' }), { code: 'NOT_FOUND' });
});

// --- dht (PKARR) ------------------------------------------------------------------

test('dns: TXT packets round-trip; compression pointers and bounds are handled', () => {
  const packet = encodePacket({ answers: [{ name: '_kwpub.example', txt: ['a'.repeat(255), 'bc'] }] });
  const { answers } = decodePacket(packet);
  assert.equal(answers[0].name, '_kwpub.example');
  assert.deepEqual(answers[0].txt, ['a'.repeat(255), 'bc']);

  // Hand-built answer whose name is a compression pointer to offset 12.
  const withPointer = Uint8Array.from([
    0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0,
    3, 0x66, 0x6f, 0x6f, 0, 0, 16, 0, 1, // question: foo TXT IN
    0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 3, 2, 0x68, 0x69,
  ]);
  assert.deepEqual(decodePacket(withPointer).answers[0], { name: 'foo', type: 16, class: 1, ttl: 60, txt: ['hi'] });
  const loop = Uint8Array.from([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12]);
  assert.throws(() => decodePacket(loop), /compression pointer/);
  assert.throws(() => decodePacket(packet.slice(0, packet.length - 3)), /past/);
  assert.throws(() => encodePacket({ answers: [{ name: 'x', txt: ['a'.repeat(256)] }] }), /255/);
});

test('dht: BEP-44 signed packets verify, tampering is a transport error', () => {
  const kp = ed25519.fromSeed(testSeed('pkarr-test'));
  const pub = makePublisher('dave', { profile: 'K-ED' });
  const z32 = pub.pkarrKey;
  assert.equal(z32.length, 52);
  assert.ok(parsePkarrKey(z32));
  assert.equal(parsePkarrKey('too-short'), null);
  const pdoc = pub.pdoc();
  const rec = pub.app('notes', makeApp('dave-app').id);
  const packet = buildKwPacket(z32, { pdoc, apps: { notes: rec } });
  assert.ok(packet.length <= PKARR_MAX_PACKET);
  const signed = signPkarrPacket(pub.pkarr, packet, 42n);
  const parsed = parseSignedPacket(z32, signed);
  assert.equal(parsed.seq, 42n);
  assert.deepEqual(extractKwRecords(z32, parsed.packet, 'notes'), { pdoc, rec });

  const tampered = Uint8Array.from(signed);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => parseSignedPacket(z32, tampered), { code: 'TRANSPORT_INVALID' });
  assert.throws(() => parseSignedPacket(z32, signPkarrPacket(kp, packet, 42n)), { code: 'TRANSPORT_INVALID' }, 'wrong signer');
  assert.throws(() => extractKwRecords(z32, parsed.packet, 'missing'), { code: 'NOT_FOUND' });
  assert.throws(() => buildKwPacket(z32, { pdoc: new Uint8Array(900), apps: { notes: rec } }), { code: 'BAD_INPUT' });
});

test('dht: DhtRail prefers the highest seq across relays and needs learned aliases', async () => {
  const world = createOfflineWorld();
  const pub = makePublisher('erin', { profile: 'K-ED' });
  const oldApp = makeApp('erin-old').id;
  const newApp = makeApp('erin-new').id;
  const newer = signPkarrPacket(pub.pkarr, buildKwPacket(pub.pkarrKey, { pdoc: pub.pdoc(), apps: { notes: pub.app('notes', newApp, { seq: 2 }) } }), 200n);
  const older = signPkarrPacket(pub.pkarr, buildKwPacket(pub.pkarrKey, { pdoc: pub.pdoc(), apps: { notes: pub.app('notes', oldApp) } }), 100n);
  const bin = (b) => () => ({ ok: true, status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) });
  world.rawHttp.set(`https://relay-a.test/${pub.pkarrKey}`, bin(older));
  world.rawHttp.set(`https://relay-b.test/${pub.pkarrKey}`, bin(newer));
  const rail = new DhtRail({ fetch: world.fetch, relays: ['https://relay-a.test', 'https://relay-b.test', 'https://relay-down.test'] });
  world.down.add('relay-down.test');
  const got = await rail.resolve({ publisher: pub.pkarrKey, slug: 'notes' });
  assert.equal(got.via, 'https://relay-b.test');
  assert.equal(got.railId, pub.pkarrKey);
  await assert.rejects(rail.resolve({ publisher: 'erin', slug: 'notes', store: new TrustStore() }), { code: 'UNKNOWN_ALIAS' });
  await assert.rejects(new DhtRail({ fetch: world.fetch }).resolve({ publisher: pub.pkarrKey, slug: 'notes' }), { code: 'RAIL_UNAVAILABLE' });
});

// --- nostr --------------------------------------------------------------------------

test('nostr: NIP-01 event ids, BIP-340 signatures, npub round-trip', () => {
  const secret = testSeed('nostr-test');
  const ev = signEvent(secret, { created_at: 1700000000, kind: 30078, tags: [['d', D_PUBLISHER]], content: 'abc' });
  assert.equal(ev.id, eventId(ev));
  assert.equal(verifyEvent(ev), true);
  assert.equal(verifyEvent({ ...ev, content: 'abd' }), false, 'content is covered by the id');
  assert.equal(verifyEvent({ ...ev, id: eventId({ ...ev, content: 'abd' }), content: 'abd' }), false, 'id is covered by the signature');
  const npub = hexToNpub(ev.pubkey);
  assert.equal(npubToHex(npub), ev.pubkey);
  assert.throws(() => npubToHex('nsec1xyz'), { code: 'BAD_INPUT' });
  assert.equal(parseNip05({ names: { alice: ev.pubkey } }, 'alice'), ev.pubkey);
  assert.throws(() => parseNip05({ names: {} }, 'alice'), { code: 'NOT_FOUND' });
});

test('nostr: pickEvent takes the newest VALID event for the d-tag', () => {
  const secret = testSeed('nostr-pick');
  const other = testSeed('nostr-other');
  const a = kwEvent(secret, { dTag: dTagForApp('notes'), bytes: Uint8Array.of(1), created_at: 10 });
  const b = kwEvent(secret, { dTag: dTagForApp('notes'), bytes: Uint8Array.of(2), created_at: 20 });
  const forgedNewest = { ...kwEvent(secret, { dTag: dTagForApp('notes'), bytes: Uint8Array.of(3), created_at: 30 }), sig: b.sig };
  const impostor = kwEvent(other, { dTag: dTagForApp('notes'), bytes: Uint8Array.of(4), created_at: 40 });
  assert.equal(pickEvent([a, b, forgedNewest, impostor], { pubkey: a.pubkey, dTag: dTagForApp('notes') }), b);
});

test('nostr: NostrRail resolves npub labels and NIP-05 names', async () => {
  const world = createOfflineWorld();
  const pub = makePublisher('frank', { profile: 'K-ED' });
  const app = makeApp('frank-app');
  world.publishNostr(pub, { pdoc: pub.pdoc(), apps: { notes: pub.app('notes', app.id) } });
  const rail = world.rails().nostr;
  const got = await rail.resolve({ publisher: pub.npub, slug: 'notes' });
  assert.equal(got.railId, pub.npub);
  world.rawHttp.set('https://example.test/.well-known/nostr.json?name=frank',
    () => ({ ok: true, status: 200, json: async () => ({ names: { frank: npubToHex(pub.npub) } }) }));
  const viaNip05 = await new NostrRail({ fetch: world.fetch, queryRelay: world.queryRelay, relays: [world.nostrRelay] })
    .resolve({ publisher: 'frank.example.test', slug: 'notes' });
  assert.equal(viaNip05.railId, pub.npub);
  await assert.rejects(rail.resolve({ publisher: pub.npub, slug: 'missing' }), { code: 'NOT_FOUND' });
  world.down.add('internet');
  await assert.rejects(rail.resolve({ publisher: pub.npub, slug: 'notes' }), { code: 'RAIL_UNAVAILABLE' });
});

// --- local, key, rail-map listing ---------------------------------------------------

test('local: the publisher book is parsed strictly and resolves petnames', async () => {
  const pub = makePublisher('mom', { profile: 'K-ED', rails: [] });
  const app = makeApp('mom-recipes');
  const pdoc = pub.pdoc();
  const rec = pub.app('recipes', app.id);
  const book = { t: BOOK_TYPE, petnames: { Mom: pub.id }, records: { [pub.id]: bookEntry(pdoc, { recipes: rec }) } };
  const rail = new LocalRail({ book });
  const got = await rail.resolve({ publisher: 'mom', slug: 'recipes' });
  assert.equal(got.railId, pub.id);
  assert.deepEqual(got.rec, rec);
  await assert.rejects(rail.resolve({ publisher: 'dad', slug: 'recipes' }), { code: 'UNKNOWN_ALIAS' });
  assert.throws(() => parsePublisherBook({ t: 'nope' }), { code: 'BAD_INPUT' });
  assert.throws(() => parsePublisherBook({ t: BOOK_TYPE, petnames: { mom: 'not-a-key' } }), { code: 'BAD_INPUT' });
  assert.throws(() => parsePublisherBook({ t: BOOK_TYPE, petnames: { 'bad petname': pub.id } }), { code: 'BAD_INPUT' });
});

test('key: <slug>.<K_pub>.key reads verified state and refuses non-keys', async () => {
  const rail = new KeyRail();
  await assert.rejects(rail.resolve({ publisher: 'alice', slug: 'x', store: new TrustStore() }), { code: 'BAD_INPUT' });
  const pub = makePublisher('gina', { profile: 'K-ED' });
  await assert.rejects(rail.resolve({ publisher: pub.id, slug: 'x', store: new TrustStore() }), { code: 'NOT_FOUND' });
});

test('railListed: only identities named in the signed rail map may speak', () => {
  const doc = {
    pub: 'p',
    rails: { at: { handle: 'alice.example', did: DID }, dht: { pkarr: 'z'.repeat(52) }, nostr: { npub: 'npub1x' } },
  };
  assert.equal(railListed('at', doc, { publisher: 'ALICE.example', railId: DID }), true);
  assert.equal(railListed('at', doc, { publisher: 'alice.example', railId: 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb' }), false);
  assert.equal(railListed('at', doc, { publisher: 'mallory.example', railId: DID }), false);
  assert.equal(railListed('dht', doc, { publisher: 'alice', railId: 'z'.repeat(52) }), true);
  assert.equal(railListed('dht', doc, { publisher: 'alice', railId: 'y'.repeat(52) }), false);
  assert.equal(railListed('nostr', doc, { publisher: 'npub1x', railId: 'npub1x' }), true);
  assert.equal(railListed('local', doc, { publisher: 'mom', railId: 'p' }), true);
  assert.equal(railListed('key', doc, { publisher: 'q', railId: 'q' }), false);
  assert.equal(railListed('ftp', doc, { publisher: 'x', railId: 'x' }), false);
});
