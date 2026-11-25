<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 The Key-Origin Web Authors. See LICENSE. -->

# Key-Origin Web (`key-web://`) — Experimental Exploration

> [!WARNING]
> **Experimental / Exploratory R&D Only — Not Production Software.**
> This repository is an open architectural exploration of DNS-free, CA-free, key-anchored Signed Web Bundles (`key-web://`) and human-readable multi-rail resolution. Expect rough edges, evolving specs, and known design trade-offs (see [docs/RELATED-WORK-AND-DESIGN-NOTES.md](docs/RELATED-WORK-AND-DESIGN-NOTES.md)).
> - **Runnable prototypes today:** `app/` (browser-hosted KeyWeb Runner + 3 local-first demo apps) and `resolver/` (Node 22+ multi-rail `.at`/`.dht`/`.nostr`/`.local`/`.key` resolver + KERI pre-rotation).
> - **Uncompiled dry-run only:** `chromium-patches/` (`KW1–KW3`) dry-run cleanly against Chromium `160.0.8176.0` source but have **not** been compiled into a browser binary.

**Unprivileged Signed Web Bundles anchored to cryptographic keys, not servers.** A DNS-free, CA-free, transport-agnostic, local-first, zero-egress web origin model with human-readable multi-rail name resolution and KERI pre-rotation.

## Repository Layout

| Directory | Status | Description |
|---|---|---|
| [`docs/`](docs/README.md) | Architecture & Specs | Plain-English explainer, full architecture specification, Chromium 160 blueprint, threat model, and [related work & design notes](docs/RELATED-WORK-AND-DESIGN-NOTES.md) (`atw://`, Web Tiles, Peergos, IWA synthesis). |
| [`app/`](app/README.md) | Runnable (Zero-Dep, Node 22+) | **KeyWeb Runner** IWA & 3 demo apps (`localpad`, `leakytracker`, `peersync-calc`), Ed25519 `.swbn` verifier, zero-egress sandbox, zero-sink/hygiene/icon gates, and 240 tests. |
| [`resolver/`](resolver/README.md) | Runnable (Zero-Dep, Node 22+) | Multi-rail `key-web://` resolver (`.at`, `.dht`, `.nostr`, `.local`, `.key`) with TOFU pinning, cross-rail equivalence, handle-hijack fail-closed detection, KERI pre-rotation, and 72 tests. |
| [`chromium-patches/`](chromium-patches/README.md) | **Experimental / Uncompiled Dry-Run** | Chromium `160.0.8176.0` native `key-web://` scheme & verifier patches (`KW1–KW3`). Verified with clean `patch --dry-run -p1` stacking (`0` fuzz, `0` offsets); **not yet compiled** against a full Chromium checkout. |

> **Experimental Status Note (`chromium-patches/`):** Patches `KW1–KW3` are uncompiled dry-run patches against Chromium `160.0.8176.0`. Before production compilation, note two tracked C++ review follow-ups: (1) `KW2` `OverrideWebPreferencesAfterNavigation` should only disable DNS prefetching for `key-web://` origins without re-enabling it when disabled by user preference; (2) `KW3` `KeyWebReaderCache::Resolve` should erase the pending entry before invoking callbacks to avoid re-entrant iterator invalidation.

## Quick Verification (Zero Dependencies, Node 22+)

```bash
# 1. KeyWeb Runner gates, unit tests, and 6-bundle ephemeral build
(cd app && npm run check && npm test && node scripts/build-swbn.mjs --out dist)

# 2. Multi-rail resolver tests and interactive demo verification
(cd resolver && npm test && npm run demo)

# 3. Chromium patch format check (dry-run apply requires a Chromium 160 checkout)
git apply --stat chromium-patches/KW*.patch
```

## License

BSD-3-Clause. See [LICENSE](LICENSE).
