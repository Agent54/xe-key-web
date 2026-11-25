<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 The Key-Origin Web Authors. See LICENSE in this directory. -->

# Key-Origin Web: Documentation

**Unprivileged Signed Web Bundles (`key-web://`).** A web that is DNS-free, CA-free, transport-agnostic, local-first, and exfiltration-proof by default.

| Document | Read it if you want… |
|---|---|
| [EXPLAINER.md](EXPLAINER.md) | The idea in plain English, with diagrams. No PhD required. |
| [ARCHITECTURE-SPEC.md](ARCHITECTURE-SPEC.md) | The precise rules: origin and URL scheme, human-readable rail names (§1.7), the zero-egress sandbox and capability ladder, transport-agnostic resolution, key rotation and naming, and a comparison matrix |
| [CHROMIUM-160-BLUEPRINT.md](CHROMIUM-160-BLUEPRINT.md) | How to build it on Chromium `160.0.8176.0`, with real files and line numbers. Layer A runs today in a SuperFrame IWA; Layer B is the native patch series KW1–KW6. |
| [THREAT-MODEL.md](THREAT-MODEL.md) | How it can be attacked, what stops each attack, what residual risk remains, and the testable security invariants |
| [RELATED-WORK-AND-DESIGN-NOTES.md](RELATED-WORK-AND-DESIGN-NOTES.md) | Comparison with Atproto Web Names (`atw://`), Web Tiles (`dasl.ing`), Peergos, and Chromium IWAs — how they combine on one `.swbn` + zero-egress runtime, plus honest lessons from prototyping & red-teaming |

**Links people can read.** You share `key-web://cool-site.lukeinth.at/` (or `.dht`, `.nostr`, `.local`). The browser resolves the name over that rail, then commits to `key-web://<kw-id>.key/`. Origin, storage, CSP, and grants are anchored to the **key only**, so every rail opens the same app and data, and a hijacked name fails closed instead of handing over your data.

## Five findings from reading the Chromium 160 source

1. **CSP `navigate-to` does not exist in Chromium**, so outbound navigation must be gated by a navigation throttle.
2. **`<link rel=preconnect>` bypasses both CSP and `X-DNS-Prefetch-Control`.** The control that does work is **`Connection-Allowlist`**, which M160 enforces inside the network service and enables by default. It is the backbone of the zero-egress guarantee.
3. **Stock IWAs are not exfiltration-proof.** Their enforced CSP allows `connect-src https: wss:`.
4. **Integrity Block v2 already tolerates and signs extra attributes**, so the `keyWeb` attribute (version, rollback chain, key-event log) is wire-compatible. The stock signature verifier, however, would reject log-rooted IDs; patch KW2 addresses this.
5. **Controlled Frame network admission is host-only, not port-aware.** Layer A compensates for this.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
