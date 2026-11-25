// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// `at` rail: ATProto handle -> DID -> DID document -> PDS -> records.
//
//   1. handle -> DID   DNS TXT `_atproto.<handle>` ("did=did:plc:..."), or
//                      HTTPS https://<handle>/.well-known/atproto-did
//   2. DID document    did:plc via a PLC directory, did:web via
//                      https://<host>/.well-known/did.json. The document must
//                      claim the handle back (alsoKnownAs at://<handle>),
//                      otherwise anyone could point a handle at their DID.
//   3. PDS             the `#atproto_pds` service endpoint
//   4. records         com.atproto.repo.getRecord for
//                        <nsid>.publisher / self     (publisher document)
//                        <nsid>.app       / <slug>   (app record)
//                      value.kw = { "$bytes": base64 } holds the signed dCBOR.
//
// The ATProto layer is DNS- and PLC-anchored and therefore NOT trusted for
// authenticity; it only delivers bytes that must verify under K_pub.
// The NSID is a placeholder until a real one is assigned (Spec App. B #6).

import { base64 } from '../encoding.mjs';
import { RailError, fetchWithTimeout } from './common.mjs';

export const DEFAULT_NSID = 'org.example.keyweb';
const DID_PLC = /^did:plc:[a-z2-7]{24}$/;
const DID_WEB = /^did:web:[a-z0-9.-]+(?:%3a[0-9]+)?$/i;
const HANDLE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

export function validateHandle(handle) {
  const h = String(handle).toLowerCase();
  if (!HANDLE.test(h)) throw new RailError('BAD_INPUT', `invalid ATProto handle: ${handle}`, { rail: 'at' });
  return h;
}

export function validateDid(did) {
  if (typeof did !== 'string' || !(DID_PLC.test(did) || DID_WEB.test(did))) {
    throw new RailError('TRANSPORT_INVALID', `unsupported or malformed DID: ${String(did).slice(0, 80)}`, { rail: 'at' });
  }
  return did;
}

/** Parse the answer of a TXT query for `_atproto.<handle>` (node:dns format). */
export function parseAtprotoTxt(records) {
  const values = (records ?? []).map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
  const dids = [...new Set(values.filter((v) => v.startsWith('did=')).map((v) => v.slice(4).trim()))];
  if (dids.length === 0) throw new RailError('NOT_FOUND', 'no did= TXT record', { rail: 'at' });
  if (dids.length > 1) throw new RailError('TRANSPORT_INVALID', 'conflicting did= TXT records', { rail: 'at' });
  return validateDid(dids[0]);
}

/** Parse the body of https://<handle>/.well-known/atproto-did. */
export function parseWellKnownAtprotoDid(text) {
  const did = String(text).split('\n')[0].trim();
  return validateDid(did);
}

export function didDocumentUrl(did, plcDirectory) {
  validateDid(did);
  if (did.startsWith('did:plc:')) return `${plcDirectory.replace(/\/$/, '')}/${did}`;
  const host = decodeURIComponent(did.slice('did:web:'.length));
  return `https://${host}/.well-known/did.json`;
}

/**
 * Validate a DID document for `did` and the handle that led to it.
 * Returns { did, pds }. Throws HANDLE_NOT_CLAIMED if the document does not
 * claim the handle back (bidirectional handle verification).
 */
export function parseDidDocument(json, did, handle) {
  if (!json || typeof json !== 'object' || json.id !== did) {
    throw new RailError('TRANSPORT_INVALID', 'DID document id mismatch', { rail: 'at' });
  }
  const aka = Array.isArray(json.alsoKnownAs) ? json.alsoKnownAs.map((s) => String(s).toLowerCase()) : [];
  if (!aka.includes(`at://${handle.toLowerCase()}`)) {
    throw new RailError('HANDLE_NOT_CLAIMED', `${did} does not claim the handle ${handle}`, { rail: 'at' });
  }
  const service = (Array.isArray(json.service) ? json.service : []).find(
    (s) => (s?.id === '#atproto_pds' || s?.id === `${did}#atproto_pds`) && s?.type === 'AtprotoPersonalDataServer',
  );
  let pds;
  try {
    pds = new URL(service?.serviceEndpoint);
  } catch {
    throw new RailError('TRANSPORT_INVALID', 'DID document has no valid #atproto_pds endpoint', { rail: 'at' });
  }
  if (pds.protocol !== 'https:') throw new RailError('TRANSPORT_INVALID', 'PDS endpoint must be https', { rail: 'at' });
  return { did, pds: pds.origin };
}

export function getRecordUrl(pds, did, collection, rkey) {
  const u = new URL('/xrpc/com.atproto.repo.getRecord', pds);
  u.searchParams.set('repo', did);
  u.searchParams.set('collection', collection);
  u.searchParams.set('rkey', rkey);
  return u.toString();
}

/** Extract the signed dCBOR bytes from a getRecord JSON response. */
export function parseGetRecordResponse(json, { did, collection, rkey }) {
  if (!json || json.uri !== `at://${did}/${collection}/${rkey}`) {
    throw new RailError('TRANSPORT_INVALID', 'getRecord returned a different record', { rail: 'at' });
  }
  const value = json.value;
  if (!value || value.$type !== collection || typeof value.kw?.$bytes !== 'string') {
    throw new RailError('TRANSPORT_INVALID', `record ${collection}/${rkey} has no kw.$bytes`, { rail: 'at' });
  }
  try {
    return base64.decode(value.kw.$bytes);
  } catch {
    throw new RailError('TRANSPORT_INVALID', 'kw.$bytes is not base64', { rail: 'at' });
  }
}

/** Build the getRecord JSON value a publisher would write (for tooling and tests). */
export function recordValue(collection, bytes) {
  return { $type: collection, kw: { $bytes: base64.encode(bytes) } };
}

export class AtRail {
  /**
   * @param {{ fetch?: typeof fetch, resolveTxt?: (name: string) => Promise<string[][]>,
   *           plcDirectory?: string, nsid?: string, timeoutMs?: number }} [options]
   */
  constructor({ fetch: fetchImpl = globalThis.fetch, resolveTxt, plcDirectory = 'https://plc.directory', nsid = DEFAULT_NSID, timeoutMs = 8000 } = {}) {
    this.name = 'at';
    this.fetch = fetchImpl;
    this.resolveTxt = resolveTxt ?? (async (name) => (await import('node:dns/promises')).resolveTxt(name));
    this.plcDirectory = plcDirectory;
    this.nsid = nsid;
    this.timeoutMs = timeoutMs;
  }

  async handleToDid(handle) {
    try {
      return parseAtprotoTxt(await this.resolveTxt(`_atproto.${handle}`));
    } catch (e) {
      if (e instanceof RailError && e.code === 'TRANSPORT_INVALID') throw e;
    }
    const res = await fetchWithTimeout(this.fetch, `https://${handle}/.well-known/atproto-did`, { rail: 'at', timeoutMs: this.timeoutMs });
    if (!res.ok) throw new RailError('NOT_FOUND', `handle ${handle} does not resolve to a DID`, { rail: 'at' });
    return parseWellKnownAtprotoDid(await res.text());
  }

  async getJson(url) {
    const res = await fetchWithTimeout(this.fetch, url, { rail: 'at', timeoutMs: this.timeoutMs, headers: { accept: 'application/json' } });
    if (res.status === 404 || res.status === 400) throw new RailError('NOT_FOUND', `${url}: ${res.status}`, { rail: 'at' });
    if (!res.ok) throw new RailError('RAIL_UNAVAILABLE', `${url}: HTTP ${res.status}`, { rail: 'at' });
    try {
      return await res.json();
    } catch {
      throw new RailError('TRANSPORT_INVALID', `${url}: not JSON`, { rail: 'at' });
    }
  }

  async resolve({ publisher, slug }) {
    const handle = validateHandle(publisher);
    const did = await this.handleToDid(handle);
    const { pds } = parseDidDocument(await this.getJson(didDocumentUrl(did, this.plcDirectory)), did, handle);
    const pubCollection = `${this.nsid}.publisher`;
    const appCollection = `${this.nsid}.app`;
    const [pdocJson, recJson] = await Promise.all([
      this.getJson(getRecordUrl(pds, did, pubCollection, 'self')),
      this.getJson(getRecordUrl(pds, did, appCollection, slug)),
    ]);
    return {
      pdoc: parseGetRecordResponse(pdocJson, { did, collection: pubCollection, rkey: 'self' }),
      rec: parseGetRecordResponse(recJson, { did, collection: appCollection, rkey: slug }),
      railId: did,
      via: pds,
    };
  }

  /** The label another resolution would use to reach this publisher on `at`. */
  labelFromRails(rails) {
    return rails?.at?.handle ?? null;
  }
}
