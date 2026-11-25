<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 The Key-Origin Web Authors. See LICENSE in this directory. -->

# Related Work & Design Notes

**Status:** Experimental exploration notes (`2026-11-26`). Captures how Key-Origin Web (`key-web://`) relates to other efforts in the decentralized / user-owned web space, what held up during prototyping and red-teaming, and how the strongest ideas across these projects could combine.

---

## 1. Why "Just the Key" Is Still Compelling

The initial naming sketch (`key-web://<app>.<publisher>.<rail>/`) was rough around the edges — especially around dotted handles and alias learning — **but the core simplicity of anchoring the origin strictly to a cryptographic key (`K_app`) genuinely holds up**:

- **Zero infrastructure required to run an app:** A `.swbn` Signed Web Bundle carries its own integrity proof and derives its own origin (`key-web://<K_app>.key/`). It works over HTTP, ATProto, Mainline DHT, Nostr, LAN, USB, or completely offline with zero DNS, zero CAs, and zero directory dependency.
- **Durable local-first storage across updates:** Unlike pure content-addressed (CID/hash) origins where changing one byte creates a brand-new origin with empty storage, a key-anchored origin lets the author ship signed updates while the user keeps their local data.
- **Transport ≠ Authority:** Mirrors, relays, PDSs, and peers are untrusted byte pipes. The browser verifies the Ed25519 signature against `K_app` before parsing HTML or executing JS.
- **Drive-by safety via subtraction, not installation:** Reusing Chromium's existing `.swbn` machinery (`SignedWebBundleReader`) while stripping *out* IWA privileges (`IsIsolatedContext() == false`, zero-egress Tier 0 by default) turns a heavy installable app format into something safe to open from a link.

---

## 2. Related Projects Comparison

| Dimension | **Key-Origin Web (`key-web://`)** | **Atproto Web Names & Origins (`atw://`)** | **Web Tiles (`dasl.ing` / `webtil.es`)** | **Peergos Custom Apps** | **Chromium IWAs (`isolated-app://`)** |
|---|---|---|---|---|---|
| **Primary job** | Stateful, updatable, local-first top-level apps safe to open from a link | Human-readable social web sites (`@handle/name`) rooted in ATProto identity | Embeddable, stateless micro-apps / rich cards inside feeds, chats, or AI threads | Capability-sandboxed local-first apps owned by the user | High-privilege installable desktop/mobile web apps (Direct Sockets, Controlled Frame) |
| **Origin anchor** | **Signing key (`K_app`)** — rail-agnostic | **ATProto DID + short name:** `base32(0x01 \|\| sha256(did \|\| 0x00 \|\| name))` | **Content hash (CID)** — immutable; new bytes = new tile | Synthetic / capability-scoped client origin | **Signing key (`webBundleId`)** |
| **Human naming & discovery** | Pluggable rails (`.at`, `.dht`, `.nostr`, `.local`, `.key`) + TOFU/pinning | `@handle/name` (`atw://handle/name`) → ATProto DID → Route Record (`agency.portable.route`) | Embedded in host posts/records (ATProto Lexicons / DASL) | Peergos social/FS paths | Manual install / enterprise policy / Single-APK |
| **Key rotation & anti-rollback** | KERI pre-rotation KEL (rail-independent; heavier for authors) | **`(rev, contentCID)` floor** + `did:plc` recovery-window reset on rotation | Not needed for immutable tiles (new version = new CID) | Peergos identity keys | Signed update manifest monotonic version |
| **Packaging** | Chromium `.swbn` Signed Web Bundles | Pluggable handler table (PDS MST, CID blobs, IPFS, Wisp, `standard.site`, HTTP — or `.swbn`) | DASL manifest + ATProto blobs (`tile://` or sandboxed `<iframe>`) | App directory in encrypted storage | Chromium `.swbn` Signed Web Bundles |
| **Network & exfiltration sandbox** | **Tier 0 zero-egress enforced in browser process** (`connect-src 'none'`, `Connection-Allowlist`, `KeyWebNavigationThrottle`, no DNS prefetch/preconnect) + opt-in Tier 1+ grants | **Inbound script integrity** (proven scripts/WASM only; no `javascript:`/`data:` escapes); outbound exfiltration blocking not yet specified | **Zero network**; host mediates all I/O via structured-clone **Tiles Data Passing Protocol** | Exfiltration-proof default + explicit user capabilities | **Not** exfiltration-proof (`connect-src https: wss:` + Direct Sockets) |
| **Deployment model** | Top-level browser origin (prototype runner today; `KW1–KW3` dry-run patches for Cr 160) | Draft spec (Revision 1, unimplemented; `atproto-web-names.szzt.app`) | Embedded sandboxed `<iframe>` on existing web, or `tile://` in dedicated clients (e.g. Beaver) | Peergos web client / local server | Shipped in Chromium behind flags / policy |

### Notes on Each Project

1. **Atproto Web Names & Origins (`atw://`, `@burrito.space` — `https://atproto-web-names.szzt.app/`):**
   - **What it nails:**
     - Clean 3-layer separation: **Resolution** (`(identity, name) → route record`), **Description** (pluggable targets & mirrors), and **Loading** (platform-specific handler).
     - **Human ergonomics:** `@handle/name` (`atw://portable.agency/blog`) handles dotted handles cleanly and never mimics DNS.
     - **Anti-rollback `(rev, contentCID)` floor:** Because an ATProto repo's `rev` (TID) increments on every social post/like, a `rev`-only floor would wrongly reject valid mirrors serving unchanged site bytes. Pairing `(rev, contentCID)` accepts stale-proof mirrors when the content CID matches while blocking superseded deployments.
     - **Key-compromise recovery:** Rotating a `did:plc` verification key resets the rollback floor *only after the `did:plc` recovery window settles*, blocking rotation-key rollback attacks while still allowing recovery.
     - **Proof-to-origin rule:** Only cryptographically *provable* targets (MST inclusion under signed commit or CID-verified bytes) receive a derived origin; *asserted* HTTP links redirect to their own origin so a compromised server never inherits accumulated storage.
   - **Trade-off vs. `key-web://`:** Because the origin is derived from `(did, short_name)`, it is permanently coupled to ATProto (`did:plc` / `plc.directory`). An out-of-band `.swbn` shared over USB, LAN, or DHT without an ATProto account cannot derive that origin.

2. **Web Tiles (`https://dasl.ing/tiles.html`, `https://webtil.es/`, Robin Berjon / DASL):**
   - **What it nails:** Solves the *embedded interactive card* problem cleanly (polls, charts, mini-tools inside social feeds, chat apps, or AI threads). Completely cuts tiles off from the network and lets hosts pass data in/out via structured-clone Tiles Protocols (`/.well-known/web-tiles/data.js`).
   - **Trade-off vs. `key-web://`:** Primarily designed around **sandboxed `<iframe>`s** and immutable content hashes (no durable updatable app storage, no progressive capability ladder for full local-first apps). Also, pure `<iframe>` CSP on standard browsers still leaks via WebRTC/TURN ICE, DNS prefetch/preconnect, and outbound navigation query strings unless backed by browser-process enforcement like `KW2`.

3. **Peergos Custom Apps (`https://peergos.org/posts/a-better-web`, `https://book.peergos.org/features/apps.html`):**
   - Directly inspired the exfiltration-proof default framing: untrusted app code should be isolated from the network by default, escaping only through explicit, narrow, user-granted capabilities rather than ambient same-origin network access.

4. **Chromium Isolated Web Apps (IWA) & WICG Web Packaging (`WICG/webpackage`):**
   - Already built the hardest browser plumbing: Ed25519 Integrity Block v2, out-of-process `SignedWebBundleReader`, and self-certifying `webBundleId`s. Key-Origin Web borrows that packaging and key-origin shape while inverting the privilege model (less privileged than `https://` rather than more privileged).

---

## 3. How `atw://`, Web Tiles, and `key-web://` Combine Cleanly

Rather than competing, the three designs sit cleanly on top of **one shared unprivileged Chromium sandbox runtime** (`.swbn` + `KW2` zero-egress enforcement):

```text
Layer 1 · Naming & Social Discovery
  Social web:    @handle/app  (atw://handle/app — @burrito.space)
  Sovereign P2P: key-web://<K_app>.key/  (raw self-certifying offline/USB/DHT link)

Layer 2 · Route Records & Anti-Rollback (for ATProto-named apps)
  ATProto DID → agency.portable.route
    • handler:   "swbn"  (Signed Web Bundle registered as a pluggable handler!)
    • target:    { bundleCid, webBundleId, mirrors: [pds, ipfs, https, dht] }
    • rollback:  (rev, contentCID) floor + did:plc recovery-window reset

Layer 3 · Shared Unprivileged Zero-Egress Browser Runtime (Chromium .swbn + KW2)
  • Verifies bundle integrity (CID match and/or Ed25519 Integrity Block)
  • Enforces Tier 0 zero-egress in the browser process:
      connect-src 'none' + Connection-Allowlist + KeyWebNavigationThrottle + no DNS hints
  • Powers:
      1. Top-level atw:// social apps   (origin = sha256(did || name))
      2. Top-level key-web:// P2P apps  (origin = K_app)
      3. Embedded Web Tiles             (closing iframe WebRTC/DNS/nav exfil leaks!)
```

### The Origin Seam Choice
If `atw://` and `key-web://` share one Chromium `.swbn` + `KW2` engine, there are two clean origin models:
1. **Dual-Mode (Recommended — lowest friction):**
   - `atw://handle/app` uses `@burrito.space`'s `sha256(did || 0x00 || name)` origin → gets seamless `did:plc` key rotation and social continuity, while `.swbn` is the transport-agnostic bundle format and `KW2` is the drive-by safe sandbox.
   - `key-web://<K_app>.key/` uses `K_app` directly → works with zero ATProto account (USB, DHT, LAN, offline). An ATProto route record can link/endorse a `key-web://` app without owning its origin.
2. **Pure Key-Origin (ATProto as directory only):**
   - `atw://handle/app` resolves the route record and hands off to `key-web://<K_app>.key/`. Same `.swbn` from ATProto or USB always shares the exact same storage, at the cost of managing key rotation separately from `did:plc`.

---

## 4. Honest Lessons & Cracks Found in Our Prototype

Prototyping (`app/` + `resolver/` + `chromium-patches/`) and adversarial cross-layer red-teaming surfaced real design cracks to fix before ever moving this past experimental status:

1. **First-contact TOFU & multi-device sync:** Without a `#:~:pin=` hash in the shared link, visit #1 still trusts whichever rail answered first, and switching devices without syncing the trust store resets TOFU.
2. **URL grammar friction (`<app>.<publisher>.<rail>`):** Splitting first label = app, last label = rail, middle = handle works mechanically for dotted handles like `lukeinth.bsky.social`, but visually mimics DNS right when trying to escape DNS. `@handle/app` (for social rails) + `key-web://<K_app>.key/` (for raw key links) is cleaner.
3. **Shorthand alias squatting (Red-Team P1 `S4-02`):** Learning short aliases (e.g. `alice.dht`) first-come from a single rail's publisher doc lets an attacker-signed doc squat desirable shorthand names. *Fix:* Require two-way confirmation on the target rail or scope learned aliases strictly to the verified publisher key.
4. **Pre-rotation anchor & rollback floor (Red-Team P1 `S4-01`, P2 `S4-04`):** In the demo runner, reading pre-rotation commitments from the latest bundle instead of an immutable inception anchor lets a stolen current key overwrite the commitment; persistent anti-rollback floors are also needed (`(rev, contentCID)` on ATProto, immutable inception KEL + monotonic `seq` floor for rail-independent keys).
5. **Web-only CSP TURN exfiltration (Red-Team P1 `S4-03`):** Under pure web/iframe Tier 0 CSP (without native `KW2`), a WebRTC `RTCPeerConnection` TURN server URL + `username` can still exfiltrate arbitrary data to an arbitrary host — proving why browser-process `Connection-Allowlist` (`webrtc=block`) in `KW2` is load-bearing for *both* Key-Origin Web and Web Tiles.
6. **Two tracked C++ follow-ups in uncompiled `KW2`/`KW3`:**
   - `KW2`: `OverrideWebPreferencesAfterNavigation` should only clear `dns_prefetching_enabled` for `key-web://` origins without re-enabling it when disabled by user preference.
   - `KW3`: `KeyWebReaderCache::Resolve` should erase the pending entry before invoking callbacks to avoid re-entrant iterator invalidation.
