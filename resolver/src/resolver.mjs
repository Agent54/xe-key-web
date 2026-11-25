// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// The resolution algorithm of Spec §1.7.5: resolve by rail, anchor to the key.
//
//   1. Ask the rail (untrusted) for the publisher document + app record.
//   2. Verify both under K_pub (K-ED/K-P256 key, or K-SAID KEL state with
//      KERI pre-rotation), and check that the rail identity that served them
//      is listed in K_pub's signed rail map.
//   3. Handle-hijack check: a name or alias this resolver already tied to a
//      K_pub may never silently start speaking for a different K_pub.
//   4. Pin check (#:~:pin=, >= 16 chars): zero-trust first click.
//   5. Binding check: a known (K_pub, slug) -> K_app binding only moves with
//      a succession proof, and even then only after explicit confirmation.
//   6. Cross-rail check: other rails in the rail map must agree; on first
//      contact without a pin, disagreement refuses to bind.
//   7. Bind (TOFU / pin / known) and return the canonical key URL.
//
// Every security failure is FAIL-CLOSED: { ok: false, failClosed: true, ... }
// with `defaultAction: "open-known"` when there is a known app to fall back
// to. The name never becomes an origin; only `canonicalUrl` is ever opened.

import { fingerprint, parseKwId, pinFor, pinMatches } from './ids.mjs';
import { canonicalKeyUrl, parseKeyWebUrl, shareLink } from './url.mjs';
import { verifyAppRecord, verifyPublisherDoc, RecordError } from './records.mjs';
import { successionProven } from './kel.mjs';
import { TrustStore } from './store.mjs';
import { KeyRail } from './rails/key.mjs';
import { RAIL_BADGES, RailError, railListed } from './rails/common.mjs';

export const FAIL_CLOSED_CODES = new Set([
  'PIN_MISMATCH', 'PIN_TOO_SHORT', 'BAD_PIN', 'KEY_MISMATCH', 'HANDLE_HIJACK', 'RAILS_DISAGREE',
  'BAD_SIGNATURE', 'HANDLE_NOT_LISTED', 'HANDLE_NOT_CLAIMED', 'PUBLISHER_MISMATCH', 'SLUG_MISMATCH',
  'RECORD_MALFORMED', 'RECORD_UNSIGNED', 'RECORD_ROLLBACK', 'PUBLISHER_RETIRED', 'TRANSPORT_INVALID',
  'KEL_DUPLICITY', 'KEL_BAD_SIGNATURE', 'KEL_NOT_PRECOMMITTED', 'KEL_BAD_CHAIN', 'KEL_BAD_SEQUENCE',
  'KEL_BAD_DIGEST', 'KEL_WRONG_ID', 'KEL_BAD_EVENT', 'KEL_AFTER_TOMB', 'KEL_UNSUPPORTED', 'KEL_EMPTY',
]);

const CROSS_RAILS = ['at', 'dht', 'nostr'];

function fail(code, message, extra = {}) {
  return { ok: false, failClosed: FAIL_CLOSED_CODES.has(code), code, message, ...extra };
}

export class KeyWebResolver {
  /**
   * @param {{ rails?: Record<string, object>, store?: TrustStore,
   *           crossCheck?: 'sync' | 'off' }} [options]
   */
  constructor({ rails = {}, store = new TrustStore(), crossCheck = 'sync' } = {}) {
    this.store = store;
    this.crossCheckMode = crossCheck;
    this.rails = { ...rails };
    if (!this.rails.key) {
      this.rails.key = new KeyRail({ fallback: (rail, label, slug) => this.fetchVia(rail, label, slug) });
    }
  }

  async fetchVia(railName, label, slug) {
    const rail = this.rails[railName];
    if (!rail) throw new RailError('RAIL_UNAVAILABLE', `no ${railName} rail configured`, { rail: railName });
    const answer = await rail.resolve({ publisher: label, slug, store: this.store });
    this.verifyAnswer(railName, label, slug, answer); // never hand back unverified bytes
    return answer;
  }

  /** Full verification of one rail answer. Throws RecordError on any failure. */
  verifyAnswer(railName, publisherLabel, slug, answer) {
    const { doc, state, kel } = verifyPublisherDoc(answer.pdoc, {
      knownKelFor: (pub) => this.store.knownKel(pub),
    });
    const rec = verifyAppRecord(answer.rec, state);
    if (rec.slug !== slug) throw new RecordError('SLUG_MISMATCH', `asked for ${slug}, got a record for ${rec.slug}`);
    if (!railListed(railName, doc, { publisher: publisherLabel, railId: answer.railId })) {
      throw new RecordError('HANDLE_NOT_LISTED',
        `the ${railName} identity ${answer.railId} is not listed in ${fingerprint(doc.pub)}'s signed rail map`);
    }
    return { doc, state, kel, rec };
  }

  aliasPublisher(railName, publisher) {
    if (railName === 'key') return publisher;
    if (railName === 'local') return this.rails.local?.book?.petnames?.[publisher] ?? this.store.petname(publisher);
    return this.store.publisherForAlias(railName, publisher);
  }

  /**
   * Resolve a key-web URL. Never throws for untrusted input; returns
   *   { ok: true, kApp, canonicalUrl, status, badges, ... }   or
   *   { ok: false, code, failClosed, message, known?, offered?, ... }
   * Options: acceptSuccession (move a binding after a VALID succession proof),
   *          crossCheck ('sync' | 'off').
   */
  async resolve(input, { acceptSuccession = false, crossCheck } = {}) {
    let parsed;
    try {
      parsed = parseKeyWebUrl(input);
    } catch (e) {
      return fail(e.code ?? 'BAD_URL', e.message);
    }
    const location = { path: parsed.path, query: parsed.query, fragment: parsed.fragment };

    if (parsed.kind === 'key') {
      const id = parseKwId(parsed.kwId);
      if (parsed.pin && !pinMatches(parsed.pin, parsed.kwId)) {
        return fail('PIN_MISMATCH', 'the pin does not commit to this key', { offered: { app: parsed.kwId } });
      }
      return {
        ok: true,
        kind: 'key',
        status: parsed.pin ? 'verified-pin' : 'self-certifying',
        kApp: parsed.kwId,
        kPub: null,
        idType: id.type,
        canonicalUrl: canonicalKeyUrl(parsed.kwId, location),
        fingerprint: fingerprint(parsed.kwId),
        badges: ['Key', ...(parsed.pin ? ['pinned'] : [])],
        rewrittenFromBareId: Boolean(parsed.rewrittenFromBareId),
      };
    }

    const { slug, publisher, rail: railName, pin } = parsed;
    const name = parsed.host;
    const rail = this.rails[railName];
    if (!rail) return fail('RAIL_UNAVAILABLE', `no ${railName} rail is configured`, { rail: railName });

    const aliasPub = this.aliasPublisher(railName, publisher);
    const known = this.store.bindingForName(name) ?? (aliasPub ? this.store.binding(aliasPub, slug) : null);

    // 1. Ask the rail.
    let answer;
    try {
      answer = await rail.resolve({ publisher, slug, store: this.store });
    } catch (e) {
      if (known && e.code !== 'BAD_INPUT') return this.cachedResult(parsed, known, e);
      const code = ['UNKNOWN_ALIAS', 'NOT_FOUND', 'TRANSPORT_INVALID', 'HANDLE_NOT_CLAIMED', 'BAD_INPUT'].includes(e.code)
        ? e.code : 'UNRESOLVABLE';
      return fail(code, e.message, { rail: railName });
    }

    // 2. Verify.
    let verified;
    try {
      verified = this.verifyAnswer(railName, publisher, slug, answer);
    } catch (e) {
      return fail(e.code ?? 'BAD_SIGNATURE', e.message, { rail: railName, ...(known ? { known: { app: known.app, pub: known.pub }, defaultAction: 'open-known' } : {}) });
    }
    const { doc, kel, rec } = verified;
    const kPub = doc.pub;
    const kApp = rec.app;
    const offered = { pub: kPub, app: kApp };

    // 3. Handle hijack: this name/alias is already tied to another publisher.
    if (aliasPub && aliasPub !== kPub) {
      return fail('HANDLE_HIJACK',
        `${railName}:${publisher} was verified as publisher ${fingerprint(aliasPub)} but now answers as ${fingerprint(kPub)}`,
        { rail: railName, known: { pub: aliasPub, app: known?.app ?? null }, offered, defaultAction: known ? 'open-known' : 'cancel' });
    }

    // 4. Pin.
    if (pin && !pinMatches(pin, kApp)) {
      return fail('PIN_MISMATCH', `the link's pin does not commit to ${fingerprint(kApp)}`,
        { rail: railName, offered, ...(known ? { known: { app: known.app, pub: known.pub }, defaultAction: 'open-known' } : {}) });
    }

    // 5. Binding.
    const bound = known ?? this.store.binding(kPub, slug);
    let succession = null;
    if (bound && bound.app !== kApp) {
      const proven = rec.succ?.from === bound.app && successionProven(bound.app, kApp, rec.succ);
      if (!proven) {
        return fail('KEY_MISMATCH',
          `${name} is bound to ${fingerprint(bound.app)}; ${railName} now offers ${fingerprint(kApp)} with no succession proof`,
          { rail: railName, known: { app: bound.app, pub: bound.pub }, offered, defaultAction: 'open-known' });
      }
      if (rec.seq <= (bound.seq ?? 0)) {
        return fail('RECORD_ROLLBACK', 'a succession record must carry a higher seq than the bound record',
          { rail: railName, known: { app: bound.app, pub: bound.pub }, offered, defaultAction: 'open-known' });
      }
      if (!acceptSuccession) {
        return {
          ok: false,
          failClosed: false,
          code: 'SUCCESSION_OFFERED',
          requiresConfirmation: true,
          message: `${fingerprint(bound.app)} was retired in favour of ${fingerprint(kApp)}; confirm to move the binding (data migration is a separate, user-confirmed step)`,
          rail: railName,
          known: { app: bound.app, pub: bound.pub },
          offered,
        };
      }
      succession = { from: bound.app };
    }
    const attributionSuspended = Boolean(bound && bound.pub !== kPub);

    // 6. Cross-rail check.
    const mode = crossCheck ?? this.crossCheckMode;
    const cross = mode === 'off' ? [] : await this.crossCheck(doc, slug, railName, answer.pdoc);
    const agree = cross.filter((c) => c.app === kApp);
    const disagree = cross.filter((c) => c.app && c.app !== kApp);
    if (disagree.length && !bound && !pin) {
      return fail('RAILS_DISAGREE', `rails disagree about ${name}; refusing to bind without a pin`, {
        rail: railName,
        offered,
        answers: [{ rail: railName, app: kApp }, ...disagree.map(({ rail: r, app }) => ({ rail: r, app }))],
      });
    }

    // 7. Bind. A publisher-key change without a KEL proof never rewrites the
    //    rail map or the binding's publisher (attribution is suspended).
    const evidence = pin ? 'pin' : succession ? 'succession' : bound ? 'known' : 'tofu';
    if (!attributionSuspended) this.store.putPublisher(doc, answer.pdoc, kel);
    this.store.bind({
      name,
      pub: attributionSuspended ? bound.pub : kPub,
      slug,
      app: kApp,
      seq: rec.seq,
      recordBytes: attributionSuspended ? undefined : answer.rec,
      rail: railName,
      evidence,
      pinned: Boolean(pin),
    });
    const badges = [RAIL_BADGES[railName]];
    const binding = this.store.binding(attributionSuspended ? bound.pub : kPub, slug);
    if (binding?.pinned) badges.push('pinned');
    if (agree.length) badges.push(`${agree.length + 1} rails agree`);
    if (disagree.length) {
      this.store.markContested(binding.pub, slug, disagree);
      badges.push('⚠ rails disagree');
    }
    if (attributionSuspended) badges.push('⚠ publisher key changed');
    this.store.save();

    return {
      ok: true,
      kind: 'name',
      status: pin ? 'verified-pin' : succession ? 'succession' : bound ? 'known' : 'first-use',
      name: { slug, publisher, rail: railName, host: name },
      kApp,
      kPub,
      canonicalUrl: canonicalKeyUrl(kApp, location),
      display: `${slug} · ${railName === 'key' ? fingerprint(publisher) : publisher}`,
      fingerprint: fingerprint(kApp),
      share: shareLink({ slug, publisher, rail: railName }, kApp, pinFor(kApp)),
      badges,
      evidence,
      crossCheck: cross,
      attributionSuspended,
      succession,
      via: answer.via,
    };
  }

  /** Query every OTHER rail in the verified rail map and report what it says. */
  async crossCheck(doc, slug, currentRail, pdocHint) {
    const out = [];
    for (const railName of CROSS_RAILS) {
      if (railName === currentRail || !doc.rails?.[railName] || !this.rails[railName]) continue;
      const rail = this.rails[railName];
      const label = rail.labelFromRails?.(doc.rails);
      if (!label) continue;
      try {
        const answer = await rail.resolve({ publisher: label, slug, store: this.store, pdocHint });
        const v = this.verifyAnswer(railName, label, slug, answer);
        if (v.doc.pub !== doc.pub) {
          out.push({ rail: railName, app: v.rec.app, pub: v.doc.pub, note: 'different publisher' });
        } else {
          out.push({ rail: railName, app: v.rec.app });
        }
      } catch (e) {
        out.push({ rail: railName, app: null, error: e.code ?? 'ERROR' });
      }
    }
    return out;
  }

  cachedResult(parsed, known, error) {
    if (parsed.pin && !pinMatches(parsed.pin, known.app)) {
      return fail('PIN_MISMATCH', `the link's pin does not commit to the cached ${fingerprint(known.app)}`,
        { known: { app: known.app, pub: known.pub } });
    }
    return {
      ok: true,
      kind: 'name',
      status: 'cached',
      name: { slug: parsed.slug, publisher: parsed.publisher, rail: parsed.rail, host: parsed.host },
      kApp: known.app,
      kPub: known.pub,
      canonicalUrl: canonicalKeyUrl(known.app, { path: parsed.path, query: parsed.query, fragment: parsed.fragment }),
      display: `${parsed.slug} · ${parsed.publisher}`,
      fingerprint: fingerprint(known.app),
      badges: [RAIL_BADGES[parsed.rail], ...(known.pinned ? ['pinned'] : []), 'offline: cached binding'],
      evidence: known.evidence,
      railError: error?.code ?? null,
    };
  }

  forget(app) {
    this.store.forgetApp(app);
    this.store.save();
  }
}
