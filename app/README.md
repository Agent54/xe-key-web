# KeyWeb Runner

A browser for **key origins**, and a proving ground for the idea.

A link names a signing key, not a server. KeyWeb Runner fetches a signed bundle for that key over whatever transport works, verifies its Ed25519 signature in the page, derives the origin from the key, and opens the app in a sandbox that starts with no way to send anything anywhere.

Links are readable. `key-web://localpad.lukeinth.at/` and `key-web://localpad.lukeinth.dht/` are the same app found through two different resolver rails, and `key-web://<key ID>.key/` is the same app with no resolver at all. All three open one key, one origin and one set of notes.

It has no dependencies, at run time or build time, and it is BSD-3-Clause.

```
node scripts/serve.mjs          # builds the signed demo bundles on first run
open http://localhost:5760/
```

You need Node 22 or newer (CI runs Node 24) and a Chromium-based browser with WebCrypto Ed25519, which is Chrome 137 or newer. It was developed and smoke-tested against Chrome 158.

## What to try

**Readable links, one key.** Click `key-web://localpad.lukeinth.at/` and write a note. The pill beside the address says `.at ✓ pinned` with the key's fingerprint; click it to see the rail, the publisher's key, the pinned Ed25519 key and what was verified. Now click `key-web://localpad.lukeinth.dht/`, then the `.key` link: same fingerprint, same notes. *Copy shareable link* puts the readable address on the clipboard.

**Kill a resolver.** On the second tab, press *Kill the .at resolver* and open `key-web://localpad.lukeinth.at/` again. It opens from the pin; the resolver was not needed. A name you have never used cannot be looked up there, and the runner says so.

**Hijack a handle.** Press *Simulate handle hijack (lukeinth.at → evil key)*. The `.at` rail now answers LocalPad's name with an attacker's key, in a record the attacker signed validly, and even attaches a rotation certificate. Open the name: `HANDLE_HIJACK`, nothing opens, and LocalPad's storage is not touched. The `.dht` name and the `.key` address still open the real app. Then press *Publish the signed key rotation on .at* to see the one way a name is allowed to change keys.

**Four transports, one origin.** Open LocalPad with *HTTP mirror* and write a note. Open it again with *P2P swarm*, then drop `dist/demo-bundles/localpad-1.0.0.swbn` on the drop zone, then use *Put it in the paste box as base64* and *Open pasted bundle*. The note is there every time, and LocalPad shows which transports it has been opened through. Storage belongs to the key.

**A poisoned peer.** Tick *Poison peer #2* and open something over the swarm. One chunk arrives with the right length and the wrong bytes; its SHA-256 does not match, peer 2 is dropped, and the chunk is fetched again from peer 3. The chunk grid shows which peer delivered what.

**An outage.** Press *Kill all servers*. Every listening socket on port 5761 is closed for real: the mirror, the four peers, the relay and the tracker. Click LocalPad's link again. The mirror fails, the swarm fails, and the app boots from the local cache with its notes.

**One flipped bit.** Press *Tamper 1 byte*. The runner flips one random bit in the bundle and verifies again: `SIGNATURE_INVALID — execution blocked before a single byte renders!` No frame is created. *Restore the original* brings it back.

**Five ways out, all closed.** Open LeakyTracker and press *Run 5 exfiltration attacks*: a `fetch()` beacon, an `<img>` tracking pixel, `navigator.sendBeacon()`, a WebSocket and a form post. The browser refuses each one. The inspector lists the violations as the browser itself reported them, and the status bar shows the tracker's own ledger: 0 requests, 0 bytes. (It will also show one *bare connection*, which is the second gap below, caught in the act.) To see that the attacks are real, open `http://legacy.localhost:5761/` in a tab: the same page with no sandbox, where all five arrive and the ledger counts them.

**Two ways out that a page cannot close.** In LeakyTracker, press *Probe the 2 known gaps*. See [What Tier 0 does not stop](#what-tier-0-does-not-stop).

**One capability at a time.** Open PeerSync Calc, work something out, and press *Sync the tape to the relay*. A grant card asks you for `net:sync-relay`, says exactly what it allows, and offers *Deny*, *Grant once* and *Grant 5 min*. The app's own sandbox never opens; the runner performs the one operation for it.

**Petnames.** On the second tab, bind "LocalPad" to the real key, then open the impostor bundle. Its signature is valid, because it is signed, just by someone else. The runner shows it as *Not "LocalPad"*, in its own empty origin. Trying to bind the same name to the impostor's key is refused as a collision.

**Key rotation.** LocalPad's signed bundle carries the hash of the only key allowed to succeed it. Try the unsigned certificate, the one forged by a stranger, and the one signed by a stolen old key for an attacker's new key: three different rejections. Apply the valid one, and the notes are carried to the new key's origin, the petname follows, and the old link opens the rotated app.

## How it works

### Two ports

| Port | What it stands for | What is on it |
| --- | --- | --- |
| 5760 | the browser | `http://localhost:5760`, the runner page; and `http://<key ID>.localhost:5760`, one real browser origin per signing key |
| 5761 | the network | `localhost` (HTTP mirror), `peer-1` to `peer-4.localhost` (swarm), `rail-at` and `rail-dht.localhost` (name resolvers), `relay.localhost`, `tracker.localhost` (also on UDP), `legacy.localhost` (the unsandboxed control) |

Both servers listen on loopback only and refuse any `Host` that is not one of those names.

### Readable names, rails and pins

| Address | How it becomes a key |
| --- | --- |
| `key-web://<app>.<publisher>.at/` | looked up on the ATProto handle rail (simulated) |
| `key-web://<app>.<publisher>.dht/` | looked up on the PKARR / Mainline DHT rail (simulated) |
| `key-web://<petname>.local/` | your own petname book; no network, and not shareable |
| `key-web://<key ID>.key/` | it already is one; the bare `key-web://<key ID>/` form works too |

A rail answers a name with a record: "this app of this publisher, on this rail, is this key", signed with the publisher's Ed25519 key (`runner/src/engine/names.js`). The signature is checked, and a record for another name or lifted from another rail is refused. But a valid signature only proves that *some* publisher key signed it, which a hijacker's does too. So the rail is never what decides:

- The first key a name resolves to is **pinned** in this browser (`runner/src/pins.js`).
- After that, the pin decides. A rail that is down is simply not needed. A rail that answers with a different key is not believed, and the name is refused as `HANDLE_HIJACK`.
- The one thing that moves a pin is a rotation certificate signed by the pinned key for the successor it committed to in advance, either already accepted here or delivered with the record and verified on the spot. A rail that later goes back to the old key is treated as out of date, not hostile.

Each name is pinned on its own, so `.at` and `.dht` are independent ways to the same key: taking over one does nothing to the other.

This is trust on first use, with the usual limit: it protects a name from the second use on. A name opened for the first time during a hijack gets the hijacker's key pinned, and afterwards that pin refuses the real key until you remove it with *Unpin*. The smoke test walks through exactly that. The `.key` address has no first use to get wrong.

### A key origin is a real origin

A Web Bundle ID is `base32(Ed25519 public key + 00 01 02)`: 56 characters, short enough to be a host name label. So `key-web://<id>/` is run at `http://<id>.localhost:5760`, and the browser's own same-origin policy keeps each key's storage apart from every other key's and from the runner's. Nothing is emulated there.

Opening a link is three steps, and the bundle is verified at each one by the same engine (`runner/src/engine/swbn.js`: WebCrypto Ed25519, with a CBOR and Web Bundle parser in plain JavaScript):

1. **The runner** verifies the bytes the transport delivered, and shows every check.
2. **The key origin's loader** (`runner/loader/loader.js`), the only page the server ever serves at a key origin, is handed the bytes, verifies them again, and insists the signing key is the one in its own host name.
3. **The key origin's service worker** (`runner/loader/sw.js`) verifies the stored bundle every time it starts, then serves that origin from the bundle and nothing else. It has no `fetch()` call and its own policy is `connect-src 'none'`.

The signature is checked over the payload's digest before the payload is parsed, so a tampered bundle fails as `SIGNATURE_INVALID` whatever the tampering hit.

### The sandbox, Tier 0

Every response a key origin serves carries this policy, whatever headers the bundle asked for:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; media-src 'self';
connect-src 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none';
frame-ancestors http://localhost:5760; require-trusted-types-for 'script'; trusted-types 'none'
```

Around it:

- The frame is `sandbox="allow-scripts allow-same-origin allow-forms"`: no popups, no top-level navigation, no downloads. (`allow-forms` is there so that `form-action 'none'` is what stops a form, and reports it.)
- The runner's own policy has `frame-src http://*.localhost:5760`, so the frame cannot be navigated to a server.
- The service worker serves a document once per boot and only after the runner asked the loader for it. An app that navigates its own frame gets a 403, including from another key's origin, and the runner closes it.
- All permission-gated features are denied by `Permissions-Policy`.

### What Tier 0 does not stop

This was measured, not assumed. Twenty ways of reaching a server were tried from inside a Tier 0 app against a raw TCP and UDP listener, in Chrome 158. Eighteen were stopped, including `fetch`, XHR, `sendBeacon`, WebSocket, EventSource, WebTransport, `fetchLater`, images, media, fonts, stylesheets, `import()`, prefetch, preload, modulepreload, `<a ping>`, forms and manifest links.

Two got through:

| Channel | What leaves | Why a page cannot stop it |
| --- | --- | --- |
| WebRTC | STUN and TURN packets over UDP, to any host and port the app names | The CSP `webrtc` directive is not implemented in Chrome ("Unrecognized Content-Security-Policy directive"), and there is no sandbox flag or permission for it |
| Bare connections | a TCP connection with nothing in it, and for a host name a DNS lookup, to anywhere | Chrome does not apply `connect-src` to `<link rel="preconnect">`. It also connects speculatively when a frame *starts* a navigation, before the policy that blocks the navigation is consulted |

Neither carries a request body, but the choice of host name, port and timing is the app's, and that is a channel. `dns-prefetch` very likely behaves like preconnect; it cannot be observed on loopback and was not confirmed.

The second one shows up without being asked for. LeakyTracker's form attack is blocked by `form-action 'none'`, no request is made and no byte of the form reaches the tracker, yet the tracker sees one connection open and close. The runner's status bar reports that as a bare connection instead of calling it nothing.

So in a stock browser, Tier 0 stops every request a Content Security Policy governs, with no data reaching the tracker in any of them, and it does not stop those two. Closing them takes the browser: the network stack has to refuse sockets to a key origin, which no page can do. The demo keeps them visible on purpose. LeakyTracker's *Probe the 2 known gaps* runs both, the tracker counts UDP datagrams and bare connections, and the runner reports what arrived. The smoke test asserts that the app, the runner and the ledger agree, and prints which gaps are open in the browser it ran in.

Also outside what this claims: timing and other side channels, and anything a person does by hand, such as copying text out.

### Capabilities

An app gets more than Tier 0 only by all three of:

1. declaring the capability in its signed descriptor, `/.well-known/key-web.json`;
2. asking for it by name; and
3. being granted it by you, once or for five minutes.

A request for an undeclared or unknown capability is refused without showing you anything. A grant never loosens the app's policy: the runner performs the one operation on the app's behalf (`runner/src/capabilities.js`, `perform()` in `runner/src/main.js`).

| Capability | What is granted |
| --- | --- |
| `net:sync-relay` | store and fetch the app's own slot on the relay: one endpoint chosen by the runner, 64 KB of text per message |
| `storage:export` | hand the runner one text file to save, under a plain file name |

### Petnames and rotation

A petname is a name you chose, stored in this browser, bound to one key. Names are compared without case, spacing or punctuation, so "Local Pad" collides with "LocalPad". A bundle's own name is shown as a claim; a claim that matches a petname bound to another key is shown as impersonation.

A rotation certificate is JSON:

```
{ "format": "key-web-rotation/1",
  "payload": "{\"from\":…,\"to\":…,\"to_key\":…,\"sequence\":1,\"next_key_digest\":…,\"issued\":…}",
  "signature_from": "<base64url Ed25519>", "signature_to": "<base64url Ed25519>" }
```

It is accepted only if the outgoing key signed it, the incoming key hashes to the `next_key_digest` in the outgoing key's own signed bundle, the incoming key signed it too, and the sequence follows the last accepted one (`runner/src/engine/rotation.js`). The pre-commitment is what defeats a stolen current key: the thief can sign, but only for a key that was fixed before the theft.

The two keys are two origins, so the runner carries `localStorage` across through the two loaders. IndexedDB is not migrated.

## The bundles

`.swbn` files here are Chromium's Signed Web Bundle format: an Integrity Block v2 (`2b`) with an Ed25519 signature stack, followed by a Web Bundle `b2`. The demo apps use `isolated-app://<id>/` URLs inside, so they are well-formed Isolated Web App bundles as well. The engine also accepts `key-web://<id>/` and origin-relative URLs, and refuses any resource addressed to another origin.

```
node scripts/build-swbn.mjs                    # everything into dist/
node scripts/build-swbn.mjs --keys-dir <dir>   # keep keys in a folder outside the repository
IWA_PACKAGER_CLI=<another packager's CLI entry> node scripts/build-swbn.mjs
```

A build writes five demo bundles under five different keys (LocalPad, LeakyTracker, PeerSync Calc, LocalPad under its rotated key, and the impostor), four rotation certificates, the signed name records for both rails (honest, hijacked and post-rotation), a catalog, and `dist/keyweb-runner-0.1.0.swbn`, the runner itself with the demo bundles inside. Each one is read back from disk and verified by `node:crypto` and by the page's WebCrypto engine, and by the other packager's `verify` command when `IWA_PACKAGER_CLI` is set.

**Keys.** By default every key exists only in the build's memory, so every build gives new origins, and notes written under the old ones are left behind. `--keys-dir` keeps them as mode-600 PEM files in a folder that must be outside the repository, so origins survive a rebuild. A key inside the repository is refused.

## Gates and tests

```
node scripts/zero-sink-check.mjs      # no HTML-string sinks, no eval, no inline script or style
node scripts/hygiene-check.mjs        # no addresses, paths, hosts, e-mail, keys or tokens
node scripts/make-icons.mjs --check   # every PNG is 8-bit RGBA, one unfiltered scanline per row
node --test tests/*.test.mjs
node scripts/build-swbn.mjs
node scripts/smoke-headless.mjs       # the whole story in headless Chrome
```

The zero-sink gate has two audited uses, both in `runner/loader/loader.js`: registering the service worker is a script-URL sink, so the loader creates one Trusted Types policy, which can only return the worker's fixed URL, and makes one registration call. They are listed with exact counts in the gate, so one more use anywhere fails it. The runner page and every app run with `trusted-types 'none'`.

The smoke test builds its own bundles into a temporary folder, uses free ports, drives the scenes above through the DevTools protocol, checks the servers' own counters as well as the page, and exits by itself with every socket closed.

## What is real and what is simulated

Real: the Ed25519 verification, in the page; the bundle format; the per-key browser origins and their storage; every policy block, enforced and reported by the browser; the closed sockets after a kill; the tracker's ledger.

Simulated: the two resolver rails. `.at` and `.dht` are two HTTP endpoints on loopback that hand out records signed at build time; nothing talks to ATProto or to the Mainline DHT, and the `did:plc:` shown for a publisher is derived from its key for display. The record signatures, the pins and the hijack refusal are real. The swarm is four HTTP endpoints on loopback. The chunking, hashing, poison detection and re-fetching are real; peer discovery and NAT traversal are not there. `key-web://` is not a scheme the browser knows, so `http://<id>.localhost:5760` stands in for it, and the dev server on port 5760 stands in for what a browser would do natively. The relay accepts any writer, because the capability in front of it is what is being shown.

## Limits

- Key origins are embedded, so the browser must allow storage and service workers for embedded sites. With third-party storage blocked, or in a private window, the runner says `STORAGE_BLOCKED` and opens nothing.
- `dist/keyweb-runner-0.1.0.swbn` is a correct, verifiable package of the runner, but it has not been run as an installed Isolated Web App. Installed, Chromium's own policy would block the plain-HTTP mirror, swarm and key-origin frames, so only verification, tampering, petnames and certificate checks would work.
- Chrome logs "An iframe which has both allow-scripts and allow-same-origin for its sandbox attribute can escape its sandboxing." That applies to frames on the embedder's own origin. Key origins are other origins and cannot reach the runner's document.

## Layout

```
runner/            the runner page, and what ships in its own signed bundle
  src/engine/      verification, CBOR, rotation, chunks, policies (shared by page, loader, worker, Node)
  loader/          the key-origin loader and service worker
demos/             LocalPad, LeakyTracker, PeerSync Calc, and the client they share
scripts/           serve, build, the gates, icons, the smoke test
tests/             node --test
```

## Licence

BSD-3-Clause. See `LICENSE`.
