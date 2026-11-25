// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The verification engine, exactly as the page runs it: WebCrypto Ed25519
// and the pure-JS CBOR and Web Bundle parsers.

import assert from 'node:assert/strict';
import { createHash, sign as cryptoSign } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { base32, base32Decode, base64, base64Decode, base64url, concat, fromHex, hex, sha256Hex } from '../runner/src/engine/bytes.js';
import { CborMap, decode, encode } from '../runner/src/engine/cbor.js';
import {
  IB_MAGIC, IB_VERSION, STEPS, VerifyError, fingerprint, idFromKey, idFromLink, inspectSwbn, isKeyId, keyFromId, keyWebOrigin,
  readDescriptor, shortId, signedData, verifyDetached, verifySwbn,
} from '../runner/src/engine/swbn.js';
import { buildWebBundle, filesToExchanges, rawPublicKey, signWebBundle, verifySignedWebBundle, webBundleId } from '../scripts/lib/swbn.mjs';
import { builtDemos, newKey, tinyBundle } from './helpers.mjs';

const bytes = (value) => new Uint8Array(Buffer.from(value));

describe('byte helpers', () => {
  test('base32 round-trips and matches a known vector', () => {
    assert.equal(base32(bytes('foobar')), 'mzxw6ytboi');
    assert.deepEqual([...base32Decode('mzxw6ytboi')], [...bytes('foobar')]);
    const random = crypto.getRandomValues(new Uint8Array(35));
    assert.deepEqual([...base32Decode(base32(random))], [...random]);
    assert.throws(() => base32Decode('MZXW'), /not base32/);
    assert.throws(() => base32Decode('mzxw6ytb1'), /not base32/);
  });

  test('base64 reads what people paste', () => {
    const data = crypto.getRandomValues(new Uint8Array(1000));
    const standard = base64(data);
    assert.equal(standard, Buffer.from(data).toString('base64'));
    assert.deepEqual([...base64Decode(standard)], [...data]);
    assert.deepEqual([...base64Decode(base64url(data))], [...data]);
    assert.deepEqual([...base64Decode(`data:application/octet-stream;base64,${standard}`)], [...data]);
    assert.deepEqual([...base64Decode(standard.replace(/(.{60})/g, '$1\n  '))], [...data]);
    for (const bad of ['', '   ', 'not base64!', 'abcde', 42, null]) assert.throws(() => base64Decode(bad), /not base64/);
  });

  test('hex round-trips and refuses upper case', () => {
    assert.equal(hex(Uint8Array.of(0, 15, 255)), '000fff');
    assert.deepEqual([...fromHex('000fff')], [0, 15, 255]);
    assert.throws(() => fromHex('0F'), /hex/);
    assert.throws(() => fromHex('abc'), /hex/);
  });
});

describe('CBOR', () => {
  test('encodes deterministically and decodes what it encodes', () => {
    const value = [7, 'text', Uint8Array.of(1, 2, 3), new CborMap([['b', 1], ['a', 2], ['aa', 3]]), [300, 70000, 5000000000]];
    const encoded = encode(value);
    const decoded = decode(encoded);
    assert.equal(decoded.end, encoded.length);
    assert.deepEqual([...encode(decoded.value)], [...encoded]);
    // Map keys are sorted by length, then bytes, whatever order they were given in.
    assert.deepEqual(decode(encode(new CborMap([['b', 1], ['aa', 3], ['a', 2]]))).value.entries.map(([key]) => key), ['a', 'b', 'aa']);
  });

  test('rejects everything outside the subset', () => {
    const rejects = (list, pattern) => assert.throws(() => decode(Uint8Array.from(list)), pattern);
    rejects([0x18, 0x05], /shortest/);            // 5 written in two bytes
    rejects([0x19, 0x00, 0xff], /shortest/);      // 255 written in three bytes
    rejects([0x5f], /indefinite/);                // indefinite-length byte string
    rejects([0x9f, 0xff], /indefinite/);          // indefinite-length array
    rejects([0x20], /unsupported/);               // negative integer
    rejects([0xf5], /unsupported/);               // true
    rejects([0xc0, 0x00], /unsupported/);         // tag
    rejects([0x43, 0x01], /past the end/);        // byte string longer than the input
    rejects([0x9a, 0xff, 0xff, 0xff, 0xff], /more items than bytes/);
    rejects([], /ran out/);
    assert.throws(() => decode(Uint8Array.from([0x62, 0xc3, 0x28])), TypeError);   // invalid UTF-8
    assert.throws(() => encode(-1), /non-negative/);
    assert.throws(() => encode(1.5), /non-negative/);
    assert.throws(() => encode(new CborMap([['a', 1], ['a', 2]])), /duplicate/);
    let deep = Uint8Array.of(0x00);
    for (let i = 0; i < 20; i++) deep = concat([Uint8Array.of(0x81), deep]);
    assert.throws(() => decode(deep), /too deep/);
  });
});

describe('keys and origins', () => {
  // RFC 8032, section 7.1, test 1.
  const RFC_KEY = fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  const RFC_SIGNATURE = fromHex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');

  test('WebCrypto verifies the RFC 8032 test vector and nothing near it', async () => {
    assert.equal(await verifyDetached(RFC_KEY, RFC_SIGNATURE, new Uint8Array(0)), true);
    assert.equal(await verifyDetached(RFC_KEY, RFC_SIGNATURE, Uint8Array.of(0)), false);
    const flipped = RFC_SIGNATURE.slice();
    flipped[10] ^= 1;
    assert.equal(await verifyDetached(RFC_KEY, flipped, new Uint8Array(0)), false);
    assert.equal(await verifyDetached(RFC_KEY.subarray(0, 31), RFC_SIGNATURE, new Uint8Array(0)), false);
    assert.equal(await verifyDetached(RFC_KEY, RFC_SIGNATURE.subarray(0, 63), new Uint8Array(0)), false);
  });

  test('the ID is base32(key + 00 01 02), and the key comes back out of it', () => {
    const id = idFromKey(RFC_KEY);
    assert.equal(id.length, 56);
    assert.match(id, /^[a-z2-7]{56}$/);
    assert.equal(id, base32(concat([RFC_KEY, Uint8Array.of(0, 1, 2)])));
    assert.ok(id.endsWith('aaic'));
    assert.deepEqual([...keyFromId(id)], [...RFC_KEY]);
    assert.equal(keyWebOrigin(id), `key-web://${id}/`);
    assert.equal(isKeyId(id), true);
    assert.equal(isKeyId(`${id.slice(0, 52)}aaaa`), false);
    assert.equal(isKeyId(id.toUpperCase()), false);
    assert.equal(isKeyId(id.slice(1)), false);
    assert.throws(() => idFromKey(new Uint8Array(31)), /32 bytes/);
    assert.equal(shortId(id), `${id.slice(0, 8)}…${id.slice(-6)}`);
  });

  test('links are parsed strictly', () => {
    const id = idFromKey(RFC_KEY);
    assert.equal(idFromLink(`key-web://${id}/`), id);
    assert.equal(idFromLink(`  key-web://${id}/notes?x=1 `), id);
    assert.equal(idFromLink(`isolated-app://${id}`), id);
    assert.equal(idFromLink(id), id);
    for (const bad of ['', 'key-web://short/', `web+key://${id}/`, `key-web://${id.slice(0, 52)}aaaa/`, 'localhost']) assert.equal(idFromLink(bad), null);
  });

  test('a fingerprint is five groups of four hex digits of SHA-256(key)', async () => {
    const print = await fingerprint(RFC_KEY);
    assert.match(print, /^([0-9a-f]{4} ){4}[0-9a-f]{4}$/);
    assert.equal(print.replace(/ /g, ''), createHash('sha256').update(RFC_KEY).digest('hex').slice(0, 20));
  });
});

describe('verifying a real signed bundle', () => {
  let demos;
  let pad;
  let swbn;
  before(async () => {
    demos = await builtDemos();
    pad = demos.find('localpad');
    swbn = demos.bytes(pad);
  });
  after(() => demos.remove());

  test('every step passes, in order, and the origin is the signing key', async () => {
    const report = await inspectSwbn(swbn, { expectedId: pad.id });
    assert.equal(report.ok, true);
    assert.equal(report.code, 'VERIFIED');
    assert.deepEqual(report.steps.map((step) => step.id), STEPS.map(([id]) => id));
    assert.ok(report.steps.every((step) => step.ok === true));
    assert.equal(report.id, pad.id);
    assert.equal(report.origin, `key-web://${pad.id}/`);
    assert.equal(report.iwaOrigin, `isolated-app://${pad.id}/`);
    assert.equal(idFromKey(report.publicKey), pad.id);
    assert.equal(report.sha256, pad.sha256);
    assert.equal(report.sha256, await sha256Hex(swbn));
    assert.equal(report.size, pad.size);
    assert.equal(report.integrityBlockLength + report.bundleLength, swbn.length);
    assert.ok(report.paths.includes('/') && report.paths.includes('/index.html') && report.paths.includes('/app.js') && report.paths.includes('/keyweb-client.js'));
    assert.deepEqual([...report.exchanges.get('/').payload], [...report.exchanges.get('/index.html').payload]);
    assert.match(report.exchanges.get('/app.js').headers['content-type'], /^text\/javascript/);
  });

  test('WebCrypto and node:crypto agree, and so does verifySwbn', async () => {
    const second = verifySignedWebBundle(swbn, { expectedId: pad.id });
    const first = await verifySwbn(swbn, { expectedId: pad.id });
    assert.equal(first.id, second.webBundleId);
    assert.equal(first.exchanges.size - 1, new Set(second.urls).size - 1);
  });

  test('all five demo bundles verify under five different keys', async () => {
    const ids = new Set();
    for (const app of demos.catalog.apps) {
      const report = await verifySwbn(demos.bytes(app), { expectedId: app.id });
      ids.add(report.id);
    }
    assert.equal(ids.size, 5);
  });

  test('one flipped bit anywhere in the payload is SIGNATURE_INVALID, before the payload is parsed', async () => {
    const start = (await inspectSwbn(swbn)).integrityBlockLength;
    const offsets = [start, start + 1, start + 9, swbn.length - 1, swbn.length - 9];
    for (let i = 0; i < 60; i++) offsets.push(start + Math.floor(Math.random() * (swbn.length - start)));
    for (const offset of offsets) {
      const copy = swbn.slice();
      copy[offset] ^= 1 << (offset % 8);
      const report = await inspectSwbn(copy, { expectedId: pad.id });
      assert.equal(report.ok, false, `offset ${offset}`);
      assert.equal(report.code, 'SIGNATURE_INVALID', `offset ${offset}`);
      assert.match(report.message, /execution blocked before a single byte renders/);
      // Fail closed: nothing learned from the bytes survives, and no later step ran.
      assert.equal(report.id, null);
      assert.equal(report.origin, null);
      assert.equal(report.exchanges.size, 0);
      const failed = report.steps.findIndex((step) => step.ok === false);
      assert.equal(report.steps[failed].id, 'signature');
      assert.ok(report.steps.slice(failed + 1).every((step) => step.ok === null));
      await assert.rejects(verifySwbn(copy), (error) => error instanceof VerifyError && error.code === 'SIGNATURE_INVALID');
      assert.throws(() => verifySignedWebBundle(copy), /signature does not verify/);
    }
  });

  test('one flipped bit anywhere in the integrity block never verifies', async () => {
    const end = (await inspectSwbn(swbn)).integrityBlockLength;
    const seen = new Set();
    for (let offset = 0; offset < end; offset++) {
      const copy = swbn.slice();
      copy[offset] ^= 1 << (offset % 8);
      const report = await inspectSwbn(copy, { expectedId: pad.id });
      assert.equal(report.ok, false, `offset ${offset}`);
      seen.add(report.code);
    }
    assert.ok(seen.has('SIGNATURE_INVALID'));
    assert.ok(seen.has('NOT_A_SIGNED_BUNDLE'));
    for (const code of seen) assert.ok(STEPS.some(([, , failure]) => failure === code) || ['UNSUPPORTED_VERSION'].includes(code), code);
  });

  test('a bundle signed by another key does not satisfy a link', async () => {
    const other = demos.find('leakytracker');
    const report = await inspectSwbn(demos.bytes(other), { expectedId: pad.id });
    assert.equal(report.code, 'ID_MISMATCH');
    assert.equal(report.id, null);
    // The impostor is a perfectly valid bundle. It is just not this key.
    const impostor = demos.catalog.apps.find((app) => app.role === 'impostor');
    assert.equal((await inspectSwbn(demos.bytes(impostor))).ok, true);
    assert.equal((await inspectSwbn(demos.bytes(impostor), { expectedId: pad.id })).code, 'ID_MISMATCH');
  });

  test('truncated, padded, empty and random input all fail without throwing', async () => {
    const cases = [
      swbn.subarray(0, 10), swbn.subarray(0, 150), swbn.subarray(0, swbn.length - 1), concat([swbn, Uint8Array.of(0)]),
      new Uint8Array(0), new Uint8Array(64), crypto.getRandomValues(new Uint8Array(4096)), bytes('<!doctype html><title>not a bundle</title>'),
    ];
    for (const input of cases) {
      const report = await inspectSwbn(input);
      assert.equal(report.ok, false);
      assert.equal(typeof report.code, 'string');
      assert.equal(report.steps.filter((step) => step.ok === false).length, 1);
    }
    for (const input of [null, undefined, 'text', [1, 2, 3], swbn.buffer]) assert.equal((await inspectSwbn(input)).code, 'NOT_A_SIGNED_BUNDLE');
    assert.equal((await inspectSwbn(swbn, { maxBytes: 1000 })).code, 'TOO_LARGE');
  });

  test('the signed descriptor is read only from a verified bundle', async () => {
    const report = await verifySwbn(swbn);
    const descriptor = readDescriptor(report);
    assert.equal(descriptor.name, 'LocalPad');
    assert.equal(descriptor.version, '1.0.0');
    assert.deepEqual(descriptor.capabilities, []);
    assert.match(descriptor.nextKeyDigest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(readDescriptor(await verifySwbn(demos.bytes(demos.find('peersync-calc')))).capabilities, ['net:sync-relay', 'storage:export']);
    const broken = swbn.slice();
    broken[broken.length - 20] ^= 1;
    assert.deepEqual(readDescriptor(await inspectSwbn(broken)), { name: null, version: null, capabilities: [], nextKeyDigest: null });
    assert.deepEqual(readDescriptor(null), { name: null, version: null, capabilities: [], nextKeyDigest: null });
  });
});

describe('bundles built to be wrong', () => {
  const block = (id, signatures) => encode([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', id]]), signatures.map(([key, signature]) => [new CborMap([['ed25519PublicKey', key]]), signature])]);
  const sha512 = (data) => new Uint8Array(createHash('sha512').update(data).digest());
  const signFor = (key, id, wbn) => new Uint8Array(cryptoSign(null, signedData(sha512(wbn), id, rawPublicKey(key)), key));

  test('an ID that names a key which did not sign is ID_KEY_MISMATCH', async () => {
    const real = tinyBundle();
    const claimed = webBundleId(rawPublicKey(newKey()));
    // The attacker signs honestly with their own key, but writes the victim's ID.
    const attacker = newKey();
    const forged = concat([block(claimed, [[rawPublicKey(attacker), signFor(attacker, claimed, real.wbn)]]), real.wbn]);
    const report = await inspectSwbn(forged);
    assert.equal(report.code, 'ID_KEY_MISMATCH');
    assert.equal(report.steps.find((step) => step.id === 'signature').ok, true);
    assert.equal(report.origin, null);
    assert.throws(() => verifySignedWebBundle(forged), /no signature comes from the key/);
  });

  test('a second, invalid signature in the stack fails the whole bundle', async () => {
    const real = tinyBundle();
    const stranger = rawPublicKey(newKey());
    const good = signFor(real.key, real.id, real.wbn);
    const report = await inspectSwbn(concat([block(real.id, [[rawPublicKey(real.key), good], [stranger, new Uint8Array(64)]]), real.wbn]));
    assert.equal(report.code, 'SIGNATURE_INVALID');
    assert.match(report.message, /signature 2 of 2/);
  });

  test('resources addressed to another origin are refused even when validly signed', async () => {
    const key = newKey();
    const id = webBundleId(rawPublicKey(key));
    const other = webBundleId(rawPublicKey(newKey()));
    const page = { status: 200, headers: { 'content-type': 'text/html' }, payload: bytes('<!doctype html>') };
    const web = 'ht' + 'tps://tracker.example/pixel.js';
    for (const url of [`isolated-app://${other}/app.js`, `key-web://${other}/app.js`, web, '//tracker.example/x.js', 'app.js', `isolated-app://${id}/app.js?x=1`, `isolated-app://${id}/app.js#x`]) {
      const signed = signWebBundle(buildWebBundle([{ ...page, url: `isolated-app://${id}/` }, { ...page, url }]), key);
      const report = await inspectSwbn(signed.swbn);
      assert.equal(report.code, 'URL_ORIGIN_MISMATCH', url);
      assert.equal(report.steps.find((step) => step.id === 'signature').ok, true);
    }
    // The same resource in all three accepted spellings is fine once, and a clash is not.
    const fine = signWebBundle(buildWebBundle([{ ...page, url: `isolated-app://${id}/` }, { ...page, url: `key-web://${id}/a.js` }, { ...page, url: '/b.js' }]), key);
    assert.deepEqual((await verifySwbn(fine.swbn)).paths, ['/', '/a.js', '/b.js']);
    const clash = signWebBundle(buildWebBundle([{ ...page, url: `isolated-app://${id}/` }, { ...page, url: `key-web://${id}/a.js` }, { ...page, url: '/a.js' }]), key);
    assert.equal((await inspectSwbn(clash.swbn)).code, 'URL_ORIGIN_MISMATCH');
  });

  test('no entry point, a bad status and a missing content type are BUNDLE_MALFORMED', async () => {
    const key = newKey();
    const id = webBundleId(rawPublicKey(key));
    const origin = `isolated-app://${id}/`;
    const good = { status: 200, headers: { 'content-type': 'text/html' }, payload: bytes('x') };
    const cases = [
      [{ ...good, url: `${origin}app.js` }],
      [{ ...good, url: origin }, { ...good, url: `${origin}gone`, status: 404 }],
      [{ ...good, url: origin }, { ...good, url: `${origin}raw`, headers: {} }],
    ];
    for (const exchanges of cases) assert.equal((await inspectSwbn(signWebBundle(buildWebBundle(exchanges), key).swbn)).code, 'BUNDLE_MALFORMED');
    // /index.html alone is enough: it also answers for /.
    const only = signWebBundle(buildWebBundle([{ ...good, url: `${origin}index.html` }]), key);
    assert.deepEqual((await verifySwbn(only.swbn)).paths, ['/', '/index.html']);
  });

  test('a signed payload that is not a web bundle is BUNDLE_MALFORMED, after the signature passed', async () => {
    const key = newKey();
    const id = webBundleId(rawPublicKey(key));
    const junk = encode([bytes('not'), bytes('a'), bytes('bundle')]);
    const report = await inspectSwbn(concat([block(id, [[rawPublicKey(key), signFor(key, id, junk)]]), junk]));
    assert.equal(report.code, 'BUNDLE_MALFORMED');
    assert.equal(report.steps.find((step) => step.id === 'signature').ok, true);
  });

  test('another version, an empty stack and extra attributes are refused', async () => {
    const real = tinyBundle();
    const signature = signFor(real.key, real.id, real.wbn);
    const key = rawPublicKey(real.key);
    const entry = [new CborMap([['ed25519PublicKey', key]]), signature];
    const withBlock = (items) => concat([encode(items), real.wbn]);
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, bytes('1b\0\0'), new CborMap([['webBundleId', real.id]]), [entry]]))).code, 'UNSUPPORTED_VERSION');
    assert.equal((await inspectSwbn(withBlock([bytes('nope'), IB_VERSION, new CborMap([['webBundleId', real.id]]), [entry]]))).code, 'NOT_A_SIGNED_BUNDLE');
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', real.id]]), []]))).code, 'INTEGRITY_BLOCK_MALFORMED');
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', real.id], ['extra', 1]]), [entry]]))).code, 'INTEGRITY_BLOCK_MALFORMED');
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', 'tooshort']]), [entry]]))).code, 'ID_MALFORMED');
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', real.id]]), [[new CborMap([['ed25519PublicKey', key.subarray(0, 31)]]), signature]]]))).code, 'INTEGRITY_BLOCK_MALFORMED');
    assert.equal((await inspectSwbn(withBlock([IB_MAGIC, IB_VERSION, new CborMap([['webBundleId', real.id]]), [[new CborMap([['ecdsaP256', key]]), signature]]]))).code, 'INTEGRITY_BLOCK_MALFORMED');
    // The untouched bundle, for contrast.
    assert.equal((await inspectSwbn(real.swbn)).ok, true);
  });

  test('a bundle may not carry headers that loosen anything: they are data, not policy', async () => {
    const loose = tinyBundle({ headers: { 'content-security-policy': "default-src *; connect-src *", 'access-control-allow-origin': '*' } });
    const report = await verifySwbn(loose.swbn);
    // The engine reports the developer's headers faithfully; policy.test.mjs shows the sandbox ignores them.
    assert.equal(report.exchanges.get('/').headers['content-security-policy'], 'default-src *; connect-src *');
  });

  test('packing is deterministic for a fixed key', () => {
    const key = newKey();
    const a = tinyBundle({ key });
    const b = tinyBundle({ key });
    assert.deepEqual([...a.swbn], [...b.swbn]);
    assert.notDeepEqual([...a.swbn], [...tinyBundle().swbn]);
    const files = [{ path: 'z.js', bytes: bytes('z') }, { path: 'index.html', bytes: bytes('i') }, { path: 'a/index.html', bytes: bytes('a') }];
    assert.deepEqual(filesToExchanges(files, a.id, {}).map((exchange) => exchange.url.slice(`isolated-app://${a.id}/`.length)), ['', 'a/', 'a/index.html', 'index.html', 'z.js']);
  });
});
