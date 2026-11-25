// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The writing half of the Signed Web Bundle format, plus a second verifier.
//
// The page's engine (runner/src/engine/swbn.js) verifies with WebCrypto.
// This file signs with node:crypto and re-verifies with node:crypto, so a
// bundle is checked by two different Ed25519 implementations before a build
// reports success, and by a third, the other packager's CLI, when
// IWA_PACKAGER_CLI is set.

import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { base64url, concat, sameBytes, utf8 } from '../../runner/src/engine/bytes.js';
import { CborMap, decode, encode, head } from '../../runner/src/engine/cbor.js';
import { NAME_FORMAT, nameMessage } from '../../runner/src/engine/names.js';
import { ROTATION_FORMAT, rotationMessage } from '../../runner/src/engine/rotation.js';
import { IB_MAGIC, IB_VERSION, WBN_MAGIC, WBN_VERSION, idFromKey, isolatedAppOrigin, keyFromId, parseWebBundle, signedData } from '../../runner/src/engine/swbn.js';

const KEY_ATTRIBUTE = 'ed25519PublicKey';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha512 = (bytes) => new Uint8Array(createHash('sha512').update(bytes).digest());

/** The 32 raw bytes of an Ed25519 public key, from a private or public KeyObject. */
export function rawPublicKey(key) {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('only Ed25519 keys can sign a bundle');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_PREFIX)) throw new Error('unexpected Ed25519 key encoding');
  return new Uint8Array(der.subarray(12));
}

export const webBundleId = idFromKey;

function publicKeyObject(rawKey) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(rawKey)]), format: 'der', type: 'spki' });
}

// ---------------------------------------------------------------- web bundle

function headerBytes(status, headers) {
  const entries = [[utf8(':status'), utf8(String(status))]];
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(lower)) throw new Error(`bad header name: ${name}`);
    if (/[\r\n\0]/.test(value)) throw new Error(`bad header value for ${name}`);
    entries.push([utf8(lower), utf8(value)]);
  }
  return encode(new CborMap(entries));
}

/** exchanges: [{url, status, headers, payload}], written in the order given. */
export function buildWebBundle(exchanges) {
  const seen = new Set();
  const responses = [];
  const located = [];
  let offset = 0;
  for (const exchange of exchanges) {
    if (seen.has(exchange.url)) throw new Error(`duplicate URL in the bundle: ${exchange.url}`);
    seen.add(exchange.url);
    const response = [headerBytes(exchange.status, exchange.headers), exchange.payload];
    const length = encode(response).length;
    responses.push(response);
    located.push([exchange.url, offset, length]);
    offset += length;
  }
  const lead = head(4, responses.length).length;
  const index = new CborMap(located.map(([url, at, length]) => [url, [at + lead, length]]));
  const sections = [index, responses];
  const lengths = ['index', encode(index).length, 'responses', encode(responses).length];
  const out = encode([WBN_MAGIC, WBN_VERSION, encode(lengths), sections, new Uint8Array(8)]);
  new DataView(out.buffer, out.byteOffset + out.length - 8, 8).setBigUint64(0, BigInt(out.length));
  return out;
}

// ---------------------------------------------------------------- signing

function integrityBlock(id, signatures) {
  return encode([
    IB_MAGIC,
    IB_VERSION,
    new CborMap([['webBundleId', id]]),
    signatures.map(([key, signature]) => [new CborMap([[KEY_ATTRIBUTE, key]]), signature]),
  ]);
}

/** Signs a bundle with one Ed25519 private KeyObject. The ID is derived from that key. */
export function signWebBundle(bundle, privateKey) {
  if (privateKey.type !== 'private') throw new Error('signing needs a private key');
  parseWebBundle(bundle);
  const rawKey = rawPublicKey(privateKey);
  const id = idFromKey(rawKey);
  const signature = new Uint8Array(cryptoSign(null, signedData(sha512(bundle), id, rawKey), privateKey));
  return { swbn: concat([integrityBlock(id, [[rawKey, signature]]), bundle]), webBundleId: id, publicKey: rawKey };
}

/**
 * The second opinion: checks a signed bundle with node:crypto and throws on
 * the first thing that is wrong. Returns {webBundleId, origin, publicKeys, bundle, urls}.
 */
export function verifySignedWebBundle(swbn, { expectedId = null } = {}) {
  const block = decode(swbn);
  if (!Array.isArray(block.value) || block.value.length !== 4) throw new Error('an integrity block is a four-item array');
  const [magic, version, attributes, stack] = block.value;
  if (!(magic instanceof Uint8Array) || !sameBytes(magic, IB_MAGIC)) throw new Error('not a signed web bundle');
  if (!(version instanceof Uint8Array) || !sameBytes(version, IB_VERSION)) throw new Error('not a version 2 integrity block');
  if (!(attributes instanceof CborMap) || attributes.entries.length !== 1) throw new Error('the integrity block attributes are malformed');
  const id = attributes.get('webBundleId');
  const idKey = keyFromId(id);
  if (expectedId !== null && id !== expectedId) throw new Error('the bundle carries a different Web Bundle ID than expected');
  if (!Array.isArray(stack) || stack.length === 0) throw new Error('the bundle is not signed');
  const signatures = stack.map((entry) => {
    const key = Array.isArray(entry) && entry.length === 2 && entry[0] instanceof CborMap && entry[0].entries.length === 1 ? entry[0].get(KEY_ATTRIBUTE) : null;
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(entry[1] instanceof Uint8Array) || entry[1].length !== 64) throw new Error('a signature entry is malformed');
    return [key, entry[1]];
  });
  if (!sameBytes(integrityBlock(id, signatures), swbn.subarray(0, block.end))) throw new Error('the integrity block is not canonically encoded');
  const bundle = swbn.subarray(block.end);
  const digest = sha512(bundle);
  for (const [key, signature] of signatures) {
    if (!cryptoVerify(null, signedData(digest, id, key), publicKeyObject(key), signature)) throw new Error('a signature does not verify: the bundle was changed or signed with another key');
  }
  if (!signatures.some(([key]) => sameBytes(key, idKey))) throw new Error('no signature comes from the key the Web Bundle ID is derived from');
  const exchanges = parseWebBundle(bundle);
  return { webBundleId: id, origin: isolatedAppOrigin(id), publicKeys: signatures.map(([key]) => key), bundle, urls: exchanges.map((exchange) => exchange.url) };
}

// ---------------------------------------------------------------- packing

const BUNDLE_MIME = {
  html: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript', json: 'application/json',
  webmanifest: 'application/manifest+json', svg: 'image/svg+xml', png: 'image/png', txt: 'text/plain', swbn: 'application/octet-stream',
};

export function bundleMime(path) {
  const match = /\.([A-Za-z0-9]+)$/.exec(path);
  return (match && BUNDLE_MIME[match[1].toLowerCase()]) || 'application/octet-stream';
}

function encodePath(path) {
  return path.split('/').map((part) => {
    if (part === '' || part === '.' || part === '..') throw new Error(`bad path in the bundle: ${path}`);
    return encodeURIComponent(part).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  }).join('/');
}

/**
 * Turns files into exchanges for an app with the given ID: one per file,
 * plus the folder URL for every index.html, sorted by URL bytes so the same
 * files always give the same bundle. The URLs are isolated-app:// ones, so
 * the result is also a well-formed Isolated Web App bundle.
 *
 * files: [{path, bytes}], headers: added to every response.
 */
export function filesToExchanges(files, id, headers) {
  const origin = isolatedAppOrigin(id);
  const entries = [];
  for (const file of files) {
    const path = encodePath(file.path);
    entries.push([path, file]);
    if (path === 'index.html') entries.push(['', file]);
    else if (path.endsWith('/index.html')) entries.push([path.slice(0, -'index.html'.length), file]);
  }
  entries.sort((a, b) => Buffer.compare(Buffer.from(a[0]), Buffer.from(b[0])));
  return entries.map(([path, file]) => ({
    url: origin + path,
    status: 200,
    headers: { 'content-type': bundleMime(file.path), ...headers },
    payload: file.bytes,
  }));
}

// ---------------------------------------------------------------- name records

/**
 * Issues the record a resolver rail hands out for one name: "this app of
 * this publisher, on this rail, is this key", signed by `signKey`, the
 * publisher's private KeyObject. A hijacker signs with their own.
 */
export function makeNameRecord({ app, publisher, rail, key, sequence, issued, signKey, rotation = [] }) {
  const payload = JSON.stringify({ app, issued, key, publisher, rail, sequence });
  return {
    format: NAME_FORMAT,
    payload,
    publisher_key: base64url(rawPublicKey(signKey)),
    signature: base64url(new Uint8Array(cryptoSign(null, nameMessage(payload), signKey))),
    ...(rotation.length ? { rotation } : {}),
  };
}

// ---------------------------------------------------------------- rotation certificates

/**
 * Issues a rotation certificate. `signFrom` and `signTo` are the private
 * KeyObjects that sign as the outgoing and the incoming key; pass null to
 * leave a signature out. `toPublicKey` is the raw key the certificate
 * names, which a forger may set to anything.
 */
export function makeRotation({ fromId, toPublicKey, sequence, nextKeyDigest = null, issued, signFrom, signTo }) {
  const payload = JSON.stringify({
    from: fromId,
    issued,
    next_key_digest: nextKeyDigest,
    sequence,
    to: idFromKey(toPublicKey),
    to_key: base64url(toPublicKey),
  });
  const signature = (role, key) => (key ? base64url(new Uint8Array(cryptoSign(null, rotationMessage(role, payload), key))) : null);
  return { format: ROTATION_FORMAT, payload, signature_from: signature('from', signFrom), signature_to: signature('to', signTo) };
}
