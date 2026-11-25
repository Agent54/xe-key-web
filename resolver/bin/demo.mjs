// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `keyweb-resolve demo`: an offline, end-to-end walk through the resolver's
// security properties using the REAL at / dht / nostr adapters over in-memory
// transports. All keys are public test vectors.

import { KeyWebResolver, TrustStore, pinFor } from '../src/index.mjs';
import { createOfflineWorld, makePublisher, makeSaidApp, makeApp } from '../src/fixtures.mjs';
import { signAppRecord, signPublisherDoc } from '../src/records.mjs';

export async function runDemo({ json = false, out = process.stdout } = {}) {
  const steps = [];
  const log = (line) => { if (!json) out.write(`${line}\n`); };
  const step = (title, result, expect) => {
    const pass = expect(result);
    steps.push({ title, pass, code: result.code ?? null, status: result.status ?? null, kApp: result.kApp ?? null, badges: result.badges ?? [] });
    log(`${pass ? 'PASS' : 'FAIL'}  ${title}`);
    log(`      -> ${result.ok ? `${result.status}  ${result.canonicalUrl}  [${result.badges.join('] [')}]` : `${result.failClosed ? 'FAIL-CLOSED ' : ''}${result.code}: ${result.message}`}`);
    return result;
  };

  const world = createOfflineWorld();
  const alice = makePublisher('alice', { profile: 'K-SAID' });
  const app = makeSaidApp('cool-site');
  const publish = (pub, apps) => {
    const records = { pdoc: pub.pdoc(), apps };
    world.publishEverywhere(pub, records);
    return records;
  };
  publish(alice, { 'cool-site': alice.app('cool-site', app.id) });

  const resolver = new KeyWebResolver({ rails: world.rails(), store: new TrustStore() });
  log(`publisher K_pub ${alice.id} (K-SAID, pre-rotated)`);
  log(`app       K_app ${app.id}\n`);

  // 1. First contact: TOFU, all three rails cross-checked.
  const first = step('first contact via .at binds by TOFU and three rails agree',
    await resolver.resolve('key-web://cool-site.alice.example/notes'),
    (r) => r.ok && r.status === 'first-use' && r.kApp === app.id && r.badges.includes('3 rails agree'));

  // 2. Cross-rail equivalence: short alias learned from the verified rail map.
  step('cool-site.alice.dht opens the SAME origin (alias learned from the signed rail map)',
    await resolver.resolve('key-web://cool-site.alice.dht/notes'),
    (r) => r.ok && r.canonicalUrl === first.canonicalUrl);
  step('cool-site.<npub>.nostr opens the SAME origin (self-certifying label)',
    await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/notes`),
    (r) => r.ok && r.canonicalUrl === first.canonicalUrl);

  // 3. AT down: DHT still opens; the AT name falls back to the cached binding.
  for (const host of ['dns', 'plc.test', 'pds-alice.test']) world.down.add(host);
  step('every .at dependency down: .dht still resolves live',
    await resolver.resolve('key-web://cool-site.alice.dht/'), (r) => r.ok && r.kApp === app.id && r.status !== 'cached');
  step('every .at dependency down: the .at name opens from the cached binding',
    await resolver.resolve('key-web://cool-site.alice.example/'), (r) => r.ok && r.status === 'cached' && r.kApp === app.id);
  for (const host of ['dns', 'plc.test', 'pds-alice.test']) world.down.delete(host);

  // 4. Pins: zero-trust first click on a fresh device, and a forged pin.
  const fresh = new KeyWebResolver({ rails: world.rails(), store: new TrustStore() });
  step('fresh device + share link pin: verified first contact',
    await fresh.resolve(`key-web://cool-site.alice.example/#:~:pin=${pinFor(app.id)}`),
    (r) => r.ok && r.status === 'verified-pin' && r.evidence === 'pin');
  step('pin for a different key: FAIL-CLOSED',
    await new KeyWebResolver({ rails: world.rails(), store: new TrustStore() })
      .resolve(`key-web://cool-site.alice.example/#:~:pin=${pinFor(makeApp('evil').id)}`),
    (r) => !r.ok && r.failClosed && r.code === 'PIN_MISMATCH');

  // 5. Handle hijack: the handle now points to an attacker's DID and keys.
  const mallory = makePublisher('mallory', { profile: 'K-ED', handle: 'alice.example', rails: ['at'] });
  const evilApp = makeApp('evil-cool-site');
  world.publishAt(mallory, { pdoc: mallory.pdoc(), apps: { 'cool-site': mallory.app('cool-site', evilApp.id) } });
  step('handle reassigned to a DID signed by K_evil: FAIL-CLOSED, known app kept',
    await resolver.resolve('key-web://cool-site.alice.example/'),
    (r) => !r.ok && r.failClosed && r.code === 'HANDLE_HIJACK' && r.known?.app === app.id && r.defaultAction === 'open-known');
  step('the hijack never touched the other rails',
    await resolver.resolve('key-web://cool-site.alice.dht/'), (r) => r.ok && r.kApp === app.id);
  world.publishAt(alice, { pdoc: alice.pdoc(), apps: { 'cool-site': alice.app('cool-site', app.id, { seq: 2 }) } });

  // 6. KERI pre-rotation of the publisher key.
  const stolen = alice.currentKey();
  alice.rotate();
  publish(alice, { 'cool-site': alice.app('cool-site', app.id, { seq: 3 }) });
  step('publisher rotates to its pre-committed next key: same K_pub, same binding',
    await resolver.resolve('key-web://cool-site.alice.example/'), (r) => r.ok && r.status === 'known' && r.kApp === app.id);
  const forged = signAppRecord({ pub: alice.id, slug: 'cool-site', app: evilApp.id, seq: 9 }, [stolen]);
  const forgedDoc = signPublisherDoc({ pub: alice.id, seq: 99, rails: alice.railMap(), kel: alice.kel }, [stolen]);
  world.publishNostr(alice, { pdoc: forgedDoc, apps: { 'cool-site': forged } });
  step('thief with the rotated-out key: signatures no longer verify',
    await resolver.resolve(`key-web://cool-site.${alice.npub}.nostr/`), (r) => !r.ok && r.failClosed && r.code === 'BAD_SIGNATURE');
  publish(alice, { 'cool-site': alice.app('cool-site', app.id, { seq: 4 }) });

  // 7. Succession: the app key retires (tomb signed by its NEXT key).
  const successor = makeApp('cool-site-v2');
  const succ = { from: app.id, kel: app.retireTo(successor.id) };
  publish(alice, { 'cool-site': alice.app('cool-site', successor.id, { seq: 5, succ }) });
  step('record moves to a new K_app WITH a tomb succession proof: offered, never silent',
    await resolver.resolve('key-web://cool-site.alice.example/'),
    (r) => !r.ok && !r.failClosed && r.code === 'SUCCESSION_OFFERED');
  step('after explicit confirmation the binding moves',
    await resolver.resolve('key-web://cool-site.alice.example/', { acceptSuccession: true }),
    (r) => r.ok && r.status === 'succession' && r.kApp === successor.id);
  publish(alice, { 'cool-site': alice.app('cool-site', makeApp('no-proof').id, { seq: 6 }) });
  step('a signed record pointing elsewhere WITHOUT a proof: FAIL-CLOSED',
    await resolver.resolve('key-web://cool-site.alice.example/'),
    (r) => !r.ok && r.failClosed && r.code === 'KEY_MISMATCH' && r.known?.app === successor.id);

  const passed = steps.filter((s) => s.pass).length;
  if (json) out.write(`${JSON.stringify({ passed, total: steps.length, steps }, null, 2)}\n`);
  else log(`\n${passed}/${steps.length} demo checks passed`);
  return passed === steps.length ? 0 : 1;
}
