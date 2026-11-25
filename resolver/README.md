<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 The Key-Origin Web Authors. -->

# `@key-web/resolver`

A zero-dependency Node ESM resolver for human-readable key-web names:

```
key-web://<app-slug>.<publisher>[.<rail>]/   ──►   key-web://<K_app>.key/
```

It implements the rule from [Spec §1.7](../docs/ARCHITECTURE-SPEC.md): **resolve by rail, anchor to the key.** A name is only a question, such as "which key does `alice.example` say is `cool-site`?". The answer is checked against Ed25519 or P-256 signatures from the publisher key (K_pub) and against local trust state. Only the resulting app key (K_app) ever becomes an origin.

- Pure JavaScript on `node:crypto`, `node:dns` and global `fetch`/`WebSocket`.
- Node ≥ 22. No npm dependencies.
- BSD-3-Clause.

```sh
npm test                       # node --test tests/   (71 tests, offline)
node bin/keyweb-resolve.mjs demo   # 14-step offline walkthrough of every guarantee
```

## What it does

| Capability | Where |
|---|---|
| URL grammar: key URLs, name URLs, bare-ID rewrite, `#:~:pin=` and `#pin=` directives, punycode kept, ports and userinfo rejected | [`src/url.mjs`](src/url.mjs) |
| kw-ids (K-ED `…aaic`, K-P256, K-SAID `…aayc`), byte-compatible with Chromium's `SignedWebBundleId`. Proxy IDs are rejected. Pins are `b32(H256("key-web-pin/v1\0"‖id))`, at least 16 characters. | [`src/ids.mjs`](src/ids.mjs) |
| Deterministic CBOR (RFC 8949 §4.2.1) with strict decode: any non-canonical byte is rejected | [`src/cbor.mjs`](src/cbor.mjs) |
| Ed25519 and P-256 (`node:crypto`), plus BIP-340 Schnorr over secp256k1 in BigInt for Nostr | [`src/crypto.mjs`](src/crypto.mjs) |
| K_pub-signed **publisher documents** (rail maps) and **app records** | [`src/records.mjs`](src/records.mjs) |
| **KERI pre-rotation** KEL: `icp`/`rot`/`tomb`, self-addressing IDs, KEL merge with duplicity detection, succession proofs | [`src/kel.mjs`](src/kel.mjs) |
| **TOFU pinning**, publisher book, learned rail aliases, persistent JSON trust store (`0600`) | [`src/store.mjs`](src/store.mjs) |
| The resolution algorithm, cross-rail checks and fail-closed results | [`src/resolver.mjs`](src/resolver.mjs) |
| Rails: `at`, `dht`, `nostr`, `local`, `key`, plus an offline mock | [`src/rails/`](src/rails/) |

## Rails and their real wire formats

| Rail | Name form | Wire handling | Self-certifying? |
|---|---|---|---|
| **`at`** (default) | `cool-site.alice.example` (rest = ATProto handle) | `_atproto.<handle>` TXT (`did=`), or `https://<handle>/.well-known/atproto-did` → DID document (did:plc through a PLC directory, or did:web). The document **must claim the handle back** (`alsoKnownAs`). Then the `#atproto_pds` endpoint, then `com.atproto.repo.getRecord` for `<nsid>.publisher/self` and `<nsid>.app/<slug>`. The signed bytes are in `value.kw.$bytes`. | No (DNS/PLC-anchored) |
| **`dht`** | `cool-site.<52-char z-base32>.dht` or a learned alias | PKARR relay body `sig(64)‖seq(8)‖packet`. The BEP-44 Ed25519 signature covers `3:seqi<seq>e1:v<len>:<packet>`. The RFC 1035 packet has `_kwpub` and `_kwapp.<slug>` TXT records (`kw1=<base64url>`). Packets are capped at 1000 bytes. | Yes, for the key label |
| **`nostr`** | `cool-site.npub1….nostr`, a NIP-05 name as labels (`alice.example.com`), or an alias | Kind-30078 addressable events with `d` = `key-web/publisher` or `key-web/app/<slug>`. The NIP-01 id is checked, then the BIP-340 signature by the npub. Content is base64url dCBOR. NIP-19 bech32 decoding. Queried with WebSocket `REQ`. | Yes, for npub |
| **`local`** | `cool-site.mom.local` | The user's own publisher book (`kw-publisher-book/1` JSON: petnames plus signed records) | Yes (user-assigned) |
| **`key`** | `<kw-id>.key` (key URL) or `cool-site.<K_pub>.key` | No lookup for key URLs. Publisher-key names use verified local state, or the rails in the publisher's rail map. | Yes |

On every rail the transport signature (PLC, PKARR or Nostr) is only a **transport check**. Authenticity always comes from the K_pub signature inside the record. The identity that served the bytes (the DID, PKARR key or npub) must also be **listed in K_pub's signed rail map** (`railListed`).

## Security behaviour

`resolve()` never throws on untrusted input. It returns `{ ok: true, canonicalUrl, kApp, … }` or `{ ok: false, code, failClosed, … }`. Every security refusal has `failClosed: true`, and offers `defaultAction: "open-known"` when a previously bound app exists.

| Situation | Result |
|---|---|
| First contact, no pin | Binds by **TOFU**, with `evidence: "tofu"` and `status: "first-use"` |
| First contact with `#:~:pin=` | Binds with `status: "verified-pin"` |
| Pin does not commit to the offered key | **`PIN_MISMATCH`** (fail closed). Nothing is bound. |
| Pin shorter than 16 characters | **`PIN_TOO_SHORT`** |
| Handle or alias already verified for K_pub now answers as another key | **`HANDLE_HIJACK`**. The binding, aliases and data stay with the known K_app. Other rails keep working. |
| Genuine records replayed from a DID, PKARR key or npub that the rail map doesn't list | **`HANDLE_NOT_LISTED`** |
| DID document doesn't claim the handle | **`HANDLE_NOT_CLAIMED`** |
| Valid K_pub record names a different K_app, with no proof | **`KEY_MISMATCH`** |
| Different K_app with a valid **succession proof** (K-SAID `tomb.successor` signed by pre-committed next keys, or a K-ED self-signed tomb) | `SUCCESSION_OFFERED` (`requiresConfirmation`). The binding only moves with `{ acceptSuccession: true }`. A lower `seq` gives `RECORD_ROLLBACK`. |
| Rails disagree on first contact without a pin | **`RAILS_DISAGREE`**: refuses to bind and lists every answer. With a pin or an existing binding, it binds and adds the badge `⚠ rails disagree` (contested). |
| Signature by a rotated-out (stolen) key | **`BAD_SIGNATURE`** |
| Two different KEL events at the same `sn` | **`KEL_DUPLICITY`** (identity frozen) |
| Rotation that reveals a key that was never pre-committed | **`KEL_NOT_PRECOMMITTED`** |
| Tampered PKARR or Nostr transport | **`TRANSPORT_INVALID`** |
| Same K_app, but K_pub changed under a known name and no KEL proof | `ok`, with `attributionSuspended` and the badge `⚠ publisher key changed`. The origin is unchanged. |
| Rail down but a binding is known | `ok`, with `status: "cached"` (offline-first) |

**Cross-rail equivalence.** A verified rail map teaches the store every alias the publisher vouches for: the handle, the handle's first label, the PKARR key, the npub and the NIP-05 name. As a result, `cool-site.alice.example`, `cool-site.alice.dht`, `cool-site.<pkarr>.dht`, `cool-site.alice.nostr`, `cool-site.<npub>.nostr` and `cool-site.<K_pub>.key` all yield the **same** `key-web://<K_app>.key/` origin, even when every `.at` dependency is down. Successful results carry an `N rails agree` badge from a synchronous cross-check (`crossCheck: 'off'` to skip it).

## CLI

```
keyweb-resolve resolve <url> [--fixtures <file> | --live] [--store <file>]
                             [--book <file>] [--no-cross-check]
                             [--accept-succession] [--json]
keyweb-resolve parse <url> [--json]
keyweb-resolve pin <kw-id> [--length <16..52>]
keyweb-resolve inspect <base64url-record>
keyweb-resolve demo [--json]
```

Exit codes: `0` ok, `1` usage, `2` unresolvable, `3` fail-closed refusal, `4` succession needs confirmation.

```sh
$ node bin/keyweb-resolve.mjs pin mix2p32okr3zpmwz3pily6bmbjlfrjvpyzljdkc4mzvpkb6lf2mqaaic
e4g5saaasdl6ahelvnt4                     # the spec's §1.7.6 test vector

$ node bin/keyweb-resolve.mjs resolve key-web://cool-site.alice.example/ --fixtures f.json --store trust.json
OK  first-use
  open:    key-web://<K_app>.key/
  …
```

- **`--fixtures`** loads offline mock rails. The format is in [`src/rails/mock.mjs`](src/rails/mock.mjs).
- **`--live`** uses the real adapters. **No relay or server is hard-coded** apart from the public PLC directory default. Configure the rest through environment variables:

  | Variable | Meaning |
  |---|---|
  | `KEYWEB_PKARR_RELAYS` | Comma-separated PKARR relay base URLs |
  | `KEYWEB_NOSTR_RELAYS` | Comma-separated `wss://` relay URLs |
  | `KEYWEB_PLC_DIRECTORY` | Overrides the PLC directory |
  | `KEYWEB_AT_NSID` | Overrides the placeholder NSID `org.example.keyweb` |

## Library

```js
import { KeyWebResolver, TrustStore, createLiveRails } from '@key-web/resolver';

const resolver = new KeyWebResolver({
  rails: createLiveRails(),                          // or your own adapters
  store: new TrustStore({ file: 'trust.json' }),
});
const r = await resolver.resolve('key-web://cool-site.alice.example/#:~:pin=…');
if (r.ok) open(r.canonicalUrl);                      // never the name URL
else if (r.failClosed) showMismatchInterstitial(r);  // r.known / r.offered / r.rail
```

A rail adapter is any object with `name`, `resolve({ publisher, slug, store }) → { pdoc, rec, railId, via }` and, optionally, `labelFromRails(rails)`. `@key-web/resolver/fixtures` exports the offline world that the tests and demo use. It builds deterministic identities and in-memory DNS, HTTPS, PKARR-relay and Nostr-relay transports that drive the **real** adapters.

## Tests

`node --test tests/`: 71 tests, all offline.

| File | Covers |
|---|---|
| `primitives` | base32, z-base32, bech32 and dCBOR strictness, plus the RFC 8032 Ed25519 test 1, the BIP-340 vector 0 and P-256 |
| `ids-url` | Spec kw-id and pin vectors, plus the full URL grammar |
| `kel-records` | Pre-rotation, thief cannot rotate, chain and digest checks, tombs, duplicity, succession proofs, K-ED/K-SAID/K-P256 records |
| `rails` | ATProto TXT, well-known, DID-doc and getRecord parsers; DNS codec (compression, bounds); PKARR signing and tampering; Nostr ids, signatures and NIP-05; publisher book; `railListed` |
| `resolver` | Every row of the security table above, for both K-ED and K-SAID publishers |
| `cli` | Every subcommand and exit code, and the demo |

All keys in [`src/fixtures.mjs`](src/fixtures.mjs) are **public test vectors**: SHA-256 of fixed labels. Hosts use the reserved `.example` and `.test` names.

## Limitations

| Area | Limitation |
|---|---|
| KEL | Only the `keys-first` profile with `icp`, `rot` and `tomb`. `rec`, `veto`, guardians, witnesses and `guardians-final` are rejected, so validation fails closed. |
| KEL clarifications | Two choices fill gaps in the spec. Event signatures use the context `key-web/kel-event/v1\0`. A `tomb` carries its revealed next keys in `k`. |
| PKARR size | K-SAID publisher documents (which carry a KEL) and succession proofs exceed PKARR's 1000-byte limit. On `dht` the resolver uses a publisher document that was already verified through another rail. A **cold** first contact via a raw PKARR key gives `NOT_FOUND` (not fail-closed) for K-SAID publishers. |
| `dht` transport | Uses PKARR relays over HTTPS. Native BEP-44 over UDP uses the same packet format but is not implemented. |
| Nostr kind and AT NSID | `30078` and `org.example.keyweb.*` are placeholders until assigned (Spec App. B #6) |
| TOFU | First contact without a pin trusts the first verified answer (cross-checked across rails). Share links therefore always carry a 20-character pin. |
