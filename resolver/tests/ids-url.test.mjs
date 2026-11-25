// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// kw-ids, pins and the key-web URL grammar (Spec §1.2, §1.3, §1.7.2, §1.7.6).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKwId, kwIdFor, pinFor, pinMatches, fingerprint, isKwId } from '../src/ids.mjs';
import { parseKeyWebUrl, canonicalKeyUrl, shareLink } from '../src/url.mjs';
import { base32, bech32, zbase32 } from '../src/encoding.mjs';
import { sha256 } from '../src/crypto.mjs';

// Worked examples from the architecture spec (not real keys).
const K_ED = 'mix2p32okr3zpmwz3pily6bmbjlfrjvpyzljdkc4mzvpkb6lf2mqaaic';
const K_SAID = 'bti22jqs6sra7zgmmebv74hg3my7sspomssfok42hnt5obyrh3hqaayc';

test('spec worked examples parse with the right type suffixes', () => {
  const ed = parseKwId(K_ED);
  assert.equal(ed.type, 'K-ED');
  assert.equal(ed.pubkey.alg, 'ed25519');
  assert.equal(ed.payload.length, 32);
  assert.ok(K_ED.endsWith('aaic'));
  const said = parseKwId(K_SAID);
  assert.equal(said.type, 'K-SAID');
  assert.equal(said.pubkey, undefined, 'a K-SAID id is a digest, not a key');
  assert.ok(K_SAID.endsWith('aayc'));
});

test('kw-ids are byte-compatible with SignedWebBundleId', () => {
  const key = sha256('some ed25519 key');
  const id = kwIdFor('K-ED', key);
  assert.equal(id.length, 56);
  assert.deepEqual(Array.from(base32.decode(id).slice(32)), [0x00, 0x01, 0x02]);
  const p = kwIdFor('K-P256', Uint8Array.of(2, ...sha256('x')));
  assert.equal(p.length, 58);
  assert.equal(parseKwId(p).type, 'K-P256');
});

test('proxy-mode, unknown suffixes and junk are rejected', () => {
  const proxy = base32.encode(Uint8Array.of(...sha256('dev'), 0x00, 0x00, 0x02));
  assert.throws(() => parseKwId(proxy), /proxy-mode/);
  const unknown = base32.encode(Uint8Array.of(...sha256('dev'), 0x00, 0x09, 0x02));
  assert.throws(() => parseKwId(unknown), /unknown kw-id type/);
  assert.equal(isKwId('cool-site'), false);
  assert.equal(isKwId(K_ED.toUpperCase()), false);
});

test('pin test vector from the spec (§1.7.6)', () => {
  assert.equal(pinFor(K_ED, 16), 'e4g5saaasdl6ahel');
  assert.equal(pinFor(K_ED), 'e4g5saaasdl6ahelvnt4');
  assert.equal(pinMatches('e4g5saaasdl6ahelvnt4', K_ED), true);
  assert.equal(pinMatches('e4g5saaasdl6ahel', K_ED), true);
  assert.equal(pinMatches('e4g5saaasdl6ahe', K_ED), false, 'below 80 bits is never accepted');
  assert.equal(pinMatches('e4g5saaasdl6ahelvnt5', K_ED), false);
  assert.throws(() => pinFor(K_ED, 8), /pin length/);
  assert.equal(fingerprint(K_ED), 'mix2p32o…aaic');
});

test('key URLs: the only origin form', () => {
  const p = parseKeyWebUrl(`key-web://${K_ED}.key/notes/a?b=c#frag`);
  assert.deepEqual([p.kind, p.kwId, p.path, p.query, p.fragment], ['key', K_ED, '/notes/a', 'b=c', 'frag']);
  assert.equal(canonicalKeyUrl(p.kwId, p), `key-web://${K_ED}.key/notes/a?b=c#frag`);
  const upper = parseKeyWebUrl(`KEY-WEB://${K_ED.toUpperCase()}.KEY/`);
  assert.equal(upper.kwId, K_ED, 'hosts are lowercased');
  const bare = parseKeyWebUrl(`key-web://${K_ED}/x`);
  assert.equal(bare.kind, 'key');
  assert.equal(bare.host, `${K_ED}.key`);
  assert.equal(bare.rewrittenFromBareId, true);
  assert.equal(parseKeyWebUrl(`web+kw://${K_ED}.key/`).kwId, K_ED, 'Layer A web+kw: links');
});

test('name hosts: default rail is at; reserved rail labels', () => {
  const at = parseKeyWebUrl('key-web://cool-site.alice.example/');
  assert.deepEqual([at.kind, at.slug, at.publisher, at.rail], ['name', 'cool-site', 'alice.example', 'at']);
  const atTld = parseKeyWebUrl('key-web://cool-site.alice.at/');
  assert.deepEqual([atTld.publisher, atTld.rail], ['alice.at', 'at'], 'alice.at is itself the ATProto handle');
  const bsky = parseKeyWebUrl('key-web://notes.alice.bsky.social/');
  assert.deepEqual([bsky.publisher, bsky.rail], ['alice.bsky.social', 'at']);
  assert.equal(parseKeyWebUrl('key-web://cool-site.alice.dht/').rail, 'dht');
  assert.equal(parseKeyWebUrl('key-web://cool-site.mom.local/').rail, 'local');
  assert.equal(parseKeyWebUrl('key-web://cool-site.alice.nostr/').rail, 'nostr');
  const key = parseKeyWebUrl(`key-web://cool-site.${K_SAID}.key/`);
  assert.deepEqual([key.kind, key.publisher, key.rail], ['name', K_SAID, 'key']);
});

test('self-certifying labels fit in one DNS label', () => {
  const pkarr = zbase32.encode(sha256('pk'));
  assert.equal(parseKeyWebUrl(`key-web://cool-site.${pkarr}.dht/`).publisher, pkarr);
  const npub = bech32.encode('npub', sha256('np'));
  assert.equal(parseKeyWebUrl(`key-web://cool-site.${npub}.nostr/`).publisher, npub);
  const nip05 = parseKeyWebUrl('key-web://cool-site.alice.example.com.nostr/');
  assert.equal(nip05.publisher, 'alice.example.com');
});

test('malformed hosts are rejected', () => {
  const bad = [
    'https://cool-site.alice.example/',
    'key-web://user@cool-site.alice.example/',
    'key-web://cool-site.alice.example:8443/',
    'key-web://cool-site.alice/',            // a lone label is not an ATProto handle
    'key-web://-bad.alice.example/',
    'key-web://cool_site.alice.example/',
    `key-web://${'a'.repeat(41)}.alice.example/`,
    'key-web://cool-site..example/',
    'key-web://cool-site.dht/',
    'key-web://cool-site.not-a-key.key/',
    'key-web://cööl.alice.example/',
  ];
  for (const url of bad) assert.throws(() => parseKeyWebUrl(url), { name: 'KeyWebUrlError' }, url);
  assert.equal(parseKeyWebUrl('key-web://xn--bcher-kva.example.dht/').slug, 'xn--bcher-kva', 'punycode stays punycode');
});

test('pins are fragment directives and are stripped', () => {
  const p = parseKeyWebUrl('key-web://cool-site.alice.example/a?q=1#route:~:pin=e4g5saaasdl6ahelvnt4');
  assert.equal(p.pin, 'e4g5saaasdl6ahelvnt4');
  assert.equal(p.fragment, 'route', 'the app keeps its own #route');
  const whole = parseKeyWebUrl('key-web://cool-site.alice.example/#pin=e4g5saaasdl6ahelvnt4');
  assert.equal(whole.pin, 'e4g5saaasdl6ahelvnt4');
  assert.equal(whole.fragment, '');
  const keyUrl = parseKeyWebUrl(`key-web://${K_ED}.key/#pin=e4g5saaasdl6ahelvnt4`);
  assert.equal(keyUrl.pin, null, 'the whole-fragment form is only for name URLs');
  assert.equal(keyUrl.fragment, 'pin=e4g5saaasdl6ahelvnt4');
  assert.throws(() => parseKeyWebUrl('key-web://cool-site.alice.example/#:~:pin=e4g5saaa'), { code: 'PIN_TOO_SHORT' });
  assert.throws(() => parseKeyWebUrl('key-web://cool-site.alice.example/#:~:pin=E4G5SAAASDL6AHEL'), { code: 'BAD_PIN' });
});

test('share links carry a pin; .local is never shared as a name', () => {
  assert.equal(shareLink({ slug: 'cool-site', publisher: 'alice.example', rail: 'at' }, K_ED, 'p'.repeat(20)),
    `key-web://cool-site.alice.example/#:~:pin=${'p'.repeat(20)}`);
  assert.equal(shareLink({ slug: 'cool-site', publisher: 'alice', rail: 'dht' }, K_ED, 'p'.repeat(20)),
    `key-web://cool-site.alice.dht/#:~:pin=${'p'.repeat(20)}`);
  assert.equal(shareLink({ slug: 'cool-site', publisher: 'mom', rail: 'local' }, K_ED, 'p'.repeat(20)),
    `key-web://${K_ED}.key/#:~:pin=${'p'.repeat(20)}`);
});
