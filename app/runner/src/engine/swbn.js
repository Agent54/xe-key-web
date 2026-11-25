// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The verification engine. It takes the raw bytes of a signed web bundle
// (.swbn) from any transport and decides, with no other input, whether they
// may run and under which origin.
//
// Integrity block, version 2b:
//   [ magic "🖋📦", version "2b\0\0", {"webBundleId": id}, [[{"ed25519PublicKey": key}, signature]] ]
//   signed data = len8(SHA-512(bundle)) + len8(integrity block with an empty
//                 signature list) + len8({"ed25519PublicKey": key})
// Web Bundle, format b2:
//   [ magic "🌐📦", version "b2\0\0", section-lengths (bytes), sections, length (8 bytes) ]
//
// The Web Bundle ID is base32(public key + 00 01 02). It is the origin:
// key-web://<id>/ here, isolated-app://<id>/ in Chromium. The bytes are the
// same format Chromium's Isolated Web Apps use.
//
// Order matters. The signature is checked over the payload's digest before
// the payload is parsed, so no unauthenticated byte past the integrity
// block is ever interpreted.
//
// Everything runs on WebCrypto and plain JavaScript, so this one file is
// what the page, the key-origin loader, the service worker and the Node
// tests all execute.

import { base32, base32Decode, concat, fromUtf8, hex, len8, sameBytes, sha256, sha512, utf8 } from './bytes.js';
import { CborMap, decode, encode, head } from './cbor.js';

export const IB_MAGIC = utf8('🖋📦');
export const IB_VERSION = utf8('2b\0\0');
export const WBN_MAGIC = utf8('🌐📦');
export const WBN_VERSION = utf8('b2\0\0');
const KEY_ATTRIBUTE = 'ed25519PublicKey';
const ID_SUFFIX = Uint8Array.of(0, 1, 2);
const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
const DESCRIPTOR_PATH = '/.well-known/key-web.json';

export const ID_PATTERN = /^[a-z2-7]{56}$/;
const ABSOLUTE_URL = /^(isolated-app|key-web):\/\/([a-z2-7]{56})(\/[^?#\s]*)$/;
const RELATIVE_URL = /^\/(?!\/)[^?#\s]*$/;

/** Every stage of verification, in the order it runs: [id, label, failure code]. */
export const STEPS = Object.freeze([
  ['size', 'Size is within limits', 'TOO_LARGE'],
  ['integrity-block', 'Integrity Block v2 header (magic 🖋📦, version 2b)', 'NOT_A_SIGNED_BUNDLE'],
  ['bundle-id', 'Web Bundle ID names an Ed25519 key', 'ID_MALFORMED'],
  ['signature-stack', 'Signature stack: 32-byte key, 64-byte signature', 'INTEGRITY_BLOCK_MALFORMED'],
  ['canonical', 'Integrity block is canonically encoded', 'NON_CANONICAL'],
  ['digest', 'SHA-512 digest of the bundle payload', 'DIGEST_FAILED'],
  ['signature', 'Ed25519 signature over the payload digest', 'SIGNATURE_INVALID'],
  ['key-binding', 'Origin is derived from the signing key', 'ID_KEY_MISMATCH'],
  ['expected-id', 'Key is the one the link named', 'ID_MISMATCH'],
  ['web-bundle', 'Web Bundle b2 structure (index, responses, lengths)', 'BUNDLE_MALFORMED'],
  ['urls', 'Every resource belongs to this key origin', 'URL_ORIGIN_MISMATCH'],
]);

export const FAILURE_TEXT = Object.freeze({
  TOO_LARGE: 'the file is larger than this runner accepts',
  NOT_A_SIGNED_BUNDLE: 'these bytes are not a signed web bundle',
  UNSUPPORTED_VERSION: 'the integrity block is not version 2',
  ID_MALFORMED: 'the Web Bundle ID does not name an Ed25519 key',
  INTEGRITY_BLOCK_MALFORMED: 'the integrity block is malformed',
  NON_CANONICAL: 'the integrity block is not canonically encoded',
  DIGEST_FAILED: 'the payload could not be hashed',
  SIGNATURE_INVALID: 'execution blocked before a single byte renders',
  ID_KEY_MISMATCH: 'no signature comes from the key the origin is derived from',
  ID_MISMATCH: 'the bundle is signed by a different key than the link named',
  BUNDLE_MALFORMED: 'the signed payload is not a well-formed web bundle',
  URL_ORIGIN_MISMATCH: 'the bundle carries a resource for another origin',
});

export class VerifyError extends Error {
  constructor(code, message, report = null) {
    super(`${code}: ${message}`);
    this.name = 'VerifyError';
    this.code = code;
    this.detail = message;
    this.report = report;
  }
}

class Fail extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------- keys and origins

export function idFromKey(rawKey) {
  if (!(rawKey instanceof Uint8Array) || rawKey.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
  return base32(concat([rawKey, ID_SUFFIX]));
}

export function keyFromId(id) {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) throw new Error('not an Ed25519 Web Bundle ID');
  const bytes = base32Decode(id);
  if (bytes.length !== 35 || bytes[32] !== 0 || bytes[33] !== 1 || bytes[34] !== 2) throw new Error('the Web Bundle ID does not end in the Ed25519 suffix');
  return bytes.subarray(0, 32);
}

export function isKeyId(id) {
  try {
    keyFromId(id);
    return true;
  } catch {
    return false;
  }
}

export const keyWebOrigin = (id) => `key-web://${id}/`;
export const isolatedAppOrigin = (id) => `isolated-app://${id}/`;

/** "abcdef…uvwxyz": enough of an ID to tell two apart at a glance. */
export const shortId = (id) => (typeof id === 'string' && id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : String(id));

/** The key's fingerprint for reading aloud: the first 10 bytes of SHA-256(key), in groups. */
export async function fingerprint(rawKey, subtle) {
  const digest = hex((await sha256(rawKey, subtle)).subarray(0, 10));
  return digest.match(/.{4}/g).join(' ');
}

/** Pulls the ID out of a key-web:// or isolated-app:// link, or returns null. */
export function idFromLink(text) {
  const match = /^(?:key-web|isolated-app):\/\/([a-z2-7]{56})(?:\.key)?(?:\/.*)?$/.exec(String(text).trim());
  if (match && isKeyId(match[1])) return match[1];
  const bare = String(text).trim();
  return isKeyId(bare) ? bare : null;
}

// ---------------------------------------------------------------- the signed data

function integrityBlock(id, signatures) {
  return encode([
    IB_MAGIC,
    IB_VERSION,
    new CborMap([['webBundleId', id]]),
    signatures.map(([key, signature]) => [new CborMap([[KEY_ATTRIBUTE, key]]), signature]),
  ]);
}

/** The exact bytes an Ed25519 signature in the stack covers. */
export function signedData(payloadDigest, id, rawKey) {
  return concat([len8(payloadDigest), len8(integrityBlock(id, [])), len8(encode(new CborMap([[KEY_ATTRIBUTE, rawKey]])))]);
}

async function ed25519Verify(subtle, rawKey, signature, data) {
  try {
    const key = await subtle.importKey('raw', rawKey, { name: 'Ed25519' }, false, ['verify']);
    return (await subtle.verify({ name: 'Ed25519' }, key, signature, data)) === true;
  } catch {
    // A key that is not a point on the curve cannot have signed anything.
    return false;
  }
}

/** Verifies a detached Ed25519 signature by a raw 32-byte public key. Never throws. */
export function verifyDetached(rawKey, signature, data, subtle = globalThis.crypto.subtle) {
  if (!(rawKey instanceof Uint8Array) || rawKey.length !== 32 || !(signature instanceof Uint8Array) || signature.length !== 64) return Promise.resolve(false);
  return ed25519Verify(subtle, rawKey, signature, data);
}

// ---------------------------------------------------------------- web bundle

/** Reads a b2 bundle, checking every length and offset. Returns [{url, status, headers, payload}]. */
export function parseWebBundle(bytes) {
  const top = decode(bytes);
  if (top.end !== bytes.length) throw new Error('bytes after the end of the bundle');
  if (!Array.isArray(top.value) || top.value.length !== 5) throw new Error('a bundle is a five-item array');
  const [magic, version, lengthBytes, sections, total] = top.value;
  if (!(magic instanceof Uint8Array) || !sameBytes(magic, WBN_MAGIC)) throw new Error('not a web bundle');
  if (!(version instanceof Uint8Array) || !sameBytes(version, WBN_VERSION)) throw new Error('not a b2 web bundle');
  if (!(total instanceof Uint8Array) || total.length !== 8 || new DataView(total.buffer, total.byteOffset, 8).getBigUint64(0) !== BigInt(bytes.length)) {
    throw new Error('the bundle length field is wrong');
  }
  if (!(lengthBytes instanceof Uint8Array)) throw new Error('the section table is malformed');
  const lengths = decode(lengthBytes);
  if (lengths.end !== lengthBytes.length || !Array.isArray(lengths.value) || !Array.isArray(sections) || lengths.value.length !== sections.length * 2) {
    throw new Error('the section table is malformed');
  }
  const named = new Map();
  sections.forEach((section, i) => {
    const name = lengths.value[i * 2];
    if (typeof name !== 'string' || named.has(name)) throw new Error('the section table is malformed');
    if (encode(section).length !== lengths.value[i * 2 + 1]) throw new Error(`section ${name} has the wrong length`);
    named.set(name, section);
  });
  const index = named.get('index');
  const responses = named.get('responses');
  if (!(index instanceof CborMap) || !Array.isArray(responses)) throw new Error('the bundle has no index or no responses');

  const byOffset = new Map();
  let offset = head(4, responses.length).length;
  for (const response of responses) {
    const length = encode(response).length;
    byOffset.set(offset, { response, length });
    offset += length;
  }
  const out = [];
  const seen = new Set();
  for (const [url, place] of index.entries) {
    const hit = Array.isArray(place) && place.length === 2 ? byOffset.get(place[0]) : null;
    if (typeof url !== 'string' || seen.has(url) || !hit || hit.length !== place[1]) throw new Error('an index entry does not point at a response');
    seen.add(url);
    if (!Array.isArray(hit.response) || hit.response.length !== 2) throw new Error('a response is malformed');
    const [headerBlock, payload] = hit.response;
    if (!(headerBlock instanceof Uint8Array) || !(payload instanceof Uint8Array)) throw new Error('a response is malformed');
    const map = decode(headerBlock);
    if (!(map.value instanceof CborMap) || map.end !== headerBlock.length) throw new Error('a response header block is malformed');
    const headers = {};
    let status = 0;
    for (const [k, v] of map.value.entries) {
      if (!(k instanceof Uint8Array) || !(v instanceof Uint8Array)) throw new Error('a response header block is malformed');
      const name = fromUtf8(k);
      if (name === ':status') status = Number(fromUtf8(v));
      else headers[name] = fromUtf8(v);
    }
    out.push({ url, status, headers, payload });
  }
  return out;
}

function pathOf(url, id) {
  const absolute = ABSOLUTE_URL.exec(url);
  if (absolute) {
    if (absolute[2] !== id) throw new Fail('URL_ORIGIN_MISMATCH', `a resource is addressed to another key: ${url.slice(0, 96)}`);
    return absolute[3];
  }
  if (RELATIVE_URL.test(url)) return url;
  throw new Fail('URL_ORIGIN_MISMATCH', `a resource is not addressed to this key origin: ${url.slice(0, 96)}`);
}

// ---------------------------------------------------------------- verification

/**
 * Runs every check and reports each one. Never throws for bad input: the
 * answer is in `ok`. Use verifySwbn() wherever a failure must stop the caller.
 *
 * Resolves with {ok, code, message, steps, size, sha256, id, origin,
 * iwaOrigin, publicKey, signatures, integrityBlockLength, bundleLength,
 * payloadSha512, exchanges (Map path -> {url, status, headers, payload}), paths}.
 */
export async function inspectSwbn(swbn, { expectedId = null, maxBytes = DEFAULT_MAX_BYTES, subtle = globalThis.crypto.subtle } = {}) {
  const report = {
    ok: false, code: null, message: null,
    steps: STEPS.map(([id, label]) => ({ id, label, ok: null, detail: '' })),
    size: swbn instanceof Uint8Array ? swbn.length : 0,
    sha256: null, id: null, origin: null, iwaOrigin: null, publicKey: null, signatures: [],
    integrityBlockLength: 0, bundleLength: 0, payloadSha512: null, exchanges: new Map(), paths: [],
  };
  const step = (id) => report.steps.find((entry) => entry.id === id);
  const pass = (id, detail = '') => Object.assign(step(id), { ok: true, detail });
  let current = STEPS[0][0];
  const begin = (id) => { current = id; };

  try {
    begin('size');
    if (!(swbn instanceof Uint8Array)) throw new Fail('NOT_A_SIGNED_BUNDLE', 'no bytes were given');
    if (swbn.length > maxBytes) throw new Fail('TOO_LARGE', `${swbn.length} bytes is over the ${maxBytes}-byte limit`);
    if (swbn.length < 16) throw new Fail('NOT_A_SIGNED_BUNDLE', 'too short to be a signed web bundle');
    report.sha256 = hex(await sha256(swbn, subtle));
    pass('size', `${swbn.length.toLocaleString('en-US')} bytes, sha256 ${report.sha256.slice(0, 16)}…`);

    begin('integrity-block');
    let block;
    try {
      block = decode(swbn);
    } catch (error) {
      throw new Fail('NOT_A_SIGNED_BUNDLE', error.message);
    }
    if (!Array.isArray(block.value) || block.value.length !== 4) throw new Fail('NOT_A_SIGNED_BUNDLE', 'an integrity block is a four-item array');
    const [magic, version, attributes, stack] = block.value;
    if (!(magic instanceof Uint8Array) || !sameBytes(magic, IB_MAGIC)) throw new Fail('NOT_A_SIGNED_BUNDLE', 'the magic bytes are not 🖋📦');
    if (!(version instanceof Uint8Array) || !sameBytes(version, IB_VERSION)) throw new Fail('UNSUPPORTED_VERSION', 'only integrity block version 2b is accepted');
    report.integrityBlockLength = block.end;
    report.bundleLength = swbn.length - block.end;
    pass('integrity-block', `${block.end} bytes of integrity block, ${report.bundleLength.toLocaleString('en-US')} bytes of payload`);

    begin('bundle-id');
    if (!(attributes instanceof CborMap) || attributes.entries.length !== 1) throw new Fail('INTEGRITY_BLOCK_MALFORMED', 'the attributes must hold exactly the Web Bundle ID');
    const id = attributes.get('webBundleId');
    let idKey;
    try {
      idKey = keyFromId(id);
    } catch (error) {
      throw new Fail('ID_MALFORMED', error.message);
    }
    pass('bundle-id', id);

    begin('signature-stack');
    if (!Array.isArray(stack) || stack.length === 0) throw new Fail('INTEGRITY_BLOCK_MALFORMED', 'the bundle is not signed');
    const signatures = stack.map((entry) => {
      const key = Array.isArray(entry) && entry.length === 2 && entry[0] instanceof CborMap && entry[0].entries.length === 1 ? entry[0].get(KEY_ATTRIBUTE) : null;
      if (!(key instanceof Uint8Array) || key.length !== 32 || !(entry[1] instanceof Uint8Array) || entry[1].length !== 64) {
        throw new Fail('INTEGRITY_BLOCK_MALFORMED', 'a signature entry is not an Ed25519 key and signature');
      }
      return [key, entry[1]];
    });
    pass('signature-stack', `${signatures.length} signature${signatures.length === 1 ? '' : 's'}`);

    begin('canonical');
    if (!sameBytes(integrityBlock(id, signatures), swbn.subarray(0, block.end))) throw new Fail('NON_CANONICAL', 're-encoding the integrity block gives different bytes');
    pass('canonical', 'byte-for-byte');

    begin('digest');
    const payload = swbn.subarray(block.end);
    const digest = await sha512(payload, subtle);
    report.payloadSha512 = hex(digest);
    pass('digest', `${report.payloadSha512.slice(0, 32)}…`);

    begin('signature');
    for (const [key, signature] of signatures) {
      const valid = await ed25519Verify(subtle, key, signature, signedData(digest, id, key));
      report.signatures.push({ publicKey: key.slice(), signature: signature.slice(), valid });
    }
    const bad = report.signatures.findIndex((entry) => !entry.valid);
    if (bad >= 0) throw new Fail('SIGNATURE_INVALID', `signature ${bad + 1} of ${signatures.length} does not verify: the bytes were changed, or another key signed them`);
    pass('signature', `${signatures.length} of ${signatures.length} valid`);

    begin('key-binding');
    if (!signatures.some(([key]) => sameBytes(key, idKey))) throw new Fail('ID_KEY_MISMATCH', 'the ID claims a key that did not sign this bundle');
    report.id = id;
    report.origin = keyWebOrigin(id);
    report.iwaOrigin = isolatedAppOrigin(id);
    report.publicKey = idKey.slice();
    pass('key-binding', report.origin);

    begin('expected-id');
    if (expectedId !== null && id !== expectedId) throw new Fail('ID_MISMATCH', `the link named ${shortId(expectedId)}, the bytes are signed by ${shortId(id)}`);
    pass('expected-id', expectedId === null ? 'no link to compare with: the bytes name their own key' : 'same key');

    begin('web-bundle');
    let parsed;
    try {
      parsed = parseWebBundle(payload);
    } catch (error) {
      throw new Fail('BUNDLE_MALFORMED', error.message);
    }
    pass('web-bundle', `${parsed.length} resource${parsed.length === 1 ? '' : 's'}`);

    begin('urls');
    const exchanges = new Map();
    for (const exchange of parsed) {
      const path = pathOf(exchange.url, id);
      if (exchanges.has(path)) throw new Fail('URL_ORIGIN_MISMATCH', `two resources claim the same path: ${path}`);
      if (exchange.status !== 200) throw new Fail('BUNDLE_MALFORMED', `a resource has status ${exchange.status}: ${path}`);
      if (typeof exchange.headers['content-type'] !== 'string') throw new Fail('BUNDLE_MALFORMED', `a resource has no content type: ${path}`);
      exchanges.set(path, exchange);
    }
    if (!exchanges.has('/') && exchanges.has('/index.html')) exchanges.set('/', exchanges.get('/index.html'));
    if (!exchanges.has('/')) throw new Fail('BUNDLE_MALFORMED', 'the bundle has no entry point (/ or /index.html)');
    report.exchanges = exchanges;
    report.paths = [...exchanges.keys()].sort();
    pass('urls', `${report.paths.length} paths, entry point /`);

    report.ok = true;
    report.code = 'VERIFIED';
    report.message = `verified: signed by the key behind ${report.origin}`;
  } catch (error) {
    const known = error instanceof Fail;
    report.ok = false;
    report.code = known ? error.code : STEPS.find(([id]) => id === current)[2];
    report.message = `${FAILURE_TEXT[report.code] || 'verification failed'} (${error.message})`;
    Object.assign(step(current), { ok: false, detail: error.message });
    // Nothing learned from bytes that failed may be used.
    report.id = null;
    report.origin = null;
    report.iwaOrigin = null;
    report.publicKey = null;
    report.exchanges = new Map();
    report.paths = [];
  }
  return report;
}

/** inspectSwbn(), but a bundle that does not verify is an exception. Fail closed. */
export async function verifySwbn(swbn, options = {}) {
  const report = await inspectSwbn(swbn, options);
  if (report.ok !== true) throw new VerifyError(report.code, report.message, report);
  return report;
}

// ---------------------------------------------------------------- the app descriptor

const CAPABILITY_NAME = /^[a-z][a-z0-9-]{0,23}:[a-z][a-z0-9-]{0,39}$/;

/**
 * What a verified bundle says about itself in /.well-known/key-web.json.
 * It is signed along with everything else, so it is the developer's word,
 * not the transport's. A missing or malformed descriptor means no name, no
 * declared capabilities and no rotation commitment.
 */
export function readDescriptor(report) {
  const empty = { name: null, version: null, capabilities: [], nextKeyDigest: null };
  const file = report && report.ok === true ? report.exchanges.get(DESCRIPTOR_PATH) : null;
  if (!file || file.payload.length > 16 * 1024) return empty;
  let data;
  try {
    data = JSON.parse(fromUtf8(file.payload));
  } catch {
    return empty;
  }
  if (data === null || typeof data !== 'object' || data.key_web !== 1) return empty;
  const text = (value, max) => (typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max) || null : null);
  const digest = typeof data.next_key_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(data.next_key_digest) ? data.next_key_digest : null;
  return {
    name: text(data.name, 64),
    version: text(data.version, 32),
    capabilities: Array.isArray(data.capabilities) ? [...new Set(data.capabilities.filter((cap) => typeof cap === 'string' && CAPABILITY_NAME.test(cap)))].slice(0, 16) : [],
    nextKeyDigest: digest,
  };
}
