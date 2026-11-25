<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 The Key-Origin Web Authors. -->

# Key-Origin Web: Chromium `160.0.8176.0` prototype patches

Three patches that turn Chromium 160 into a browser that can open **unprivileged, key-addressed Signed Web Bundles** at `key-web://<kw-id>.key/`. You don't install anything, and the apps have **no network egress** by default.

| Patch | What it does | Blueprint sections |
|---|---|---|
| [`KW1-register-key-web-unprivileged-scheme.patch`](KW1-register-key-web-unprivileged-scheme.patch) | Registers `key-web://` as a standard, secure, CORS, service-worker and web-storage scheme. Makes it structurally impossible for key-web to become an isolated context. Adds `KeyWebOrigin` and the `kKeyOriginWeb` feature. | KW1 |
| [`KW2-key-web-exfiltration-proof-csp-and-navigation-throttle.patch`](KW2-key-web-exfiltration-proof-csp-and-navigation-throttle.patch) | Adds the exfiltration-proof CSP, `Connection-Allowlist`, header sanitizer and Permissions-Policy, plus `KeyWebNavigationThrottle`, the popup gate and DNS-prefetch/preconnect suppression. | KW3, KW4 (navigation) |
| [`KW3-key-web-signed-bundle-url-loader-factory.patch`](KW3-key-web-signed-bundle-url-loader-factory.patch) | Adds `KeyWebURLLoaderFactory`, which serves verified `.swbn` releases through `SignedWebBundleReader` and `SignedWebBundleIntegrityBlock`. Also adds a per-key `StoragePartition` and the bare-ID rewrite. | KW2, KW4 (storage) |

The blueprint and spec live in [`../docs/CHROMIUM-160-BLUEPRINT.md`](../docs/CHROMIUM-160-BLUEPRINT.md) and [`../docs/ARCHITECTURE-SPEC.md`](../docs/ARCHITECTURE-SPEC.md).

## Verify and apply

```sh
# Dry-run every patch against a pristine tree (0 rejects, 0 fuzz, 0 offsets),
# then check that the series stacks. Never modifies the tree.
./verify-patches.sh /path/to/chromium/src

# Apply, in order:
for p in KW1-*.patch KW2-*.patch KW3-*.patch; do patch -p1 -d /path/to/chromium/src < "$p"; done
```

Verified against the `160.0.8176.0` reference checkout (`chrome/VERSION` 160/0/8176/0):

```
PASS  KW1-register-key-web-unprivileged-scheme.patch  (15 files, 0 rejects, 0 fuzz, 0 offsets)
PASS  KW2-key-web-exfiltration-proof-csp-and-navigation-throttle.patch  (16 files, 0 rejects, 0 fuzz, 0 offsets)
PASS  KW3-key-web-signed-bundle-url-loader-factory.patch  (13 files, 0 rejects, 0 fuzz, 0 offsets)
PASS  series KW1 -> KW2 -> KW3 stacks with git apply (no fuzz)
```

Each patch also passes `git apply --check`. They are plain `-p1` unified diffs with `a/` and `b/` prefixes.

> **Build status.** The patches are text-verified against the tree, and every API they call was checked against the reference sources. They have **not been compiled**: the reference checkout is source-only and lacks `//url` and `//net`. Expect a short round of compile fixes on a full checkout. Run `gn format` over the touched `BUILD.gn` files.

At runtime, set `--enable-features=KeyOriginWeb`. The scheme is registered regardless of the flag. Without the flag no loader factory and no throttle are installed, so `key-web://` navigations fail safely.

## KW1: an unprivileged scheme, enforced at registration

- **`chrome/common/chrome_content_client.cc`** adds `key-web` to `kChromeStandardURLSchemes` and to the secure, CORS, service-worker and web-storage lists. It is deliberately **absent** from `isolated_app_schemes`, `csp_bypassing_schemes`, `code_cache_schemes`, `extension_schemes` and `local_schemes`.
- **`content/public/common/content_client.h` and `content/common/url_schemes.cc`** add a new list, `Schemes::never_isolated_context_schemes`. `RegisterContentSchemes()` `CHECK`s three things for every entry:
  - it is standard and secure;
  - it is absent from every privileged list;
  - it never reaches `blink::CommonSchemeRegistry::RegisterURLSchemeAsIsolatedApp()`.

  Blink only reports `IsIsolatedContext()` for schemes registered there, so a key-web document **always** sees `IsIsolatedContext() == false`. An accidental edit to the embedder lists crashes at startup instead of shipping a privilege escalation.
- **`ChromeContentBrowserClient::ShouldUrlUseApplicationIsolationLevel()`** returns `false` for key-web before any IWA logic runs. This also covers `blob:` and `filesystem:` URLs whose inner origin is key-web. COOP+COEP can make a key-web page `crossOriginIsolated`, but it never reaches `kIsolatedApplication`.
- **`components/webapps/key_web/key_web_origin.*`** accepts only `key-web://<kw-id>.key`.
  - It rejects name hosts such as `cool-site.alice.example`, bare IDs, ports, userinfo and proxy-mode IDs.
  - The storage partition domain is `"k" + b64(SHA-256("key-web-partition/v1" || origin))`.
- **`//url` is not part of the reference checkout.** Chromium keeps embedder schemes out of `url/url_constants.h` anyway: `isolated-app` lives in `components/webapps/isolated_web_apps/scheme.h`. `kKeyWebScheme` follows that precedent in `components/webapps/key_web/scheme.h`.

## KW2: zero egress in Tier 0

| Layer | Mechanism | Covers |
|---|---|---|
| L1 CSP | `default-src 'self'; connect-src 'none'; img-src 'self' data: blob:; form-action 'none'`, plus hardening directives (`object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'self'`, `fenced-frame-src 'none'`, trusted types, and others) that never add a network source. Appended next to the app's own CSP, so the app can only tighten it. | fetch, XHR, WebSocket, beacon, subresources, forms |
| L2 `Connection-Allowlist` | `(response-origin);redirects=block;webrtc=block`, where response-origin is the non-network key-web origin | DNS resolution, socket preconnect, prefetch, WebTransport, WebRTC (enforced in the network service) |
| L3 `KeyWebNavigationThrottle` | Runs on `WillStartRequest` and `WillRedirectRequest`, keyed on the initiator origin | navigations, meta refresh, `mailto:` and other external schemes, cross-key navigation |
| L3 popups | `CanCreateWindow()` refuses every cross-origin window from a key-web opener | `window.open`, `target=_blank` |
| L5 sanitizer | Strips app `Report-To`, `Reporting-Endpoints`, `NEL`, `*-Report-Only`, `Connection-Allowlist*`, `Link`, `Refresh`, `Speculation-Rules`, `Set-Cookie`, `Alt-Svc`, and more. Also removes `report-uri` and `report-to` directives from app CSP. | reporting and hint side channels |
| Hints | Injects `X-DNS-Prefetch-Control: off`. Clears `WebPreferences::dns_prefetching_enabled` while the main frame is key-web. `NetworkHintsHandlerImpl` drops `PrefetchDNS` and `Preconnect` from key-web frames and frames nested in them. | `<link rel=dns-prefetch>`, `<link rel=preconnect>` |

**Why a throttle and not CSP?** Chromium 160 does not implement `navigate-to`: it is absent from `network::mojom::CSPDirectiveName`, and Blink ignores unknown directives. A policy that names it would give false assurance, so outbound navigation is decided in the browser process.

`KeyWebNavigationThrottle` decides each navigation through a pure function, `key_web::DecideKeyWebNavigation()`. That function has its own unit tests.

| Navigation initiated by a key-web document | Verdict |
|---|---|
| Same key-web origin, including same-origin `blob:` | `PROCEED` (NG1) |
| `about:blank`, `about:srcdoc`, `data:` | `PROCEED` (no network) |
| Prerender or speculation rules | `CANCEL` (NG7) |
| Cross-origin **subframe** | `BLOCK_REQUEST`, always: ambient egress can't be user-mediated |
| Cross-origin top level **without** a user gesture | `BLOCK_REQUEST`, with a console message (NG4) |
| Cross-origin top level **with** a user gesture | `CANCEL`, then a browser-owned tab-modal prompt (described below) |

The prompt shows the **full, untruncated URL** and offers *Open in new tab*, *Copy address* and *Cancel*, with *Cancel* as the default. *Open in new tab* starts a **browser-initiated** navigation in a new foreground tab, so it has no opener, no referrer and no key-web initiator (NG4 and NG5).

The DNS-prefetch preference and the hint filter are belt and braces. `Connection-Allowlist` is the load-bearing control for `<link rel=preconnect>`, which bypasses both CSP and `X-DNS-Prefetch-Control` in M160.

## KW3: verified bundles, no install ceremony

```
key-web://<kw-id>/x  ──BrowserURLHandler──▶  key-web://<kw-id>.key/x
                                               │
                         KeyWebURLLoaderFactory (non-network, GET/HEAD only)
                                               │
       KeyWebReaderCache: <profile>/Key Web Bundles/<kw-id>.swbn
         ├─ web_app::SignedWebBundleReader::Create(..., verify_signatures=true)
         │    integrity block parsed out of process; every signature verified
         │    over SHA-512(unsigned bundle) by SignedWebBundleSignatureVerifier
         ├─ ValidateKeyWebIntegrityBlock(SignedWebBundleIntegrityBlock):
         │    webBundleId == kw-id
         │    some VERIFIED signature key derives to kw-id (self-certifying;
         │      IWA key-rotation data is never consulted)
         │    `keyWeb` attribute present, v == 1, seq uint (author intent)
         └─ every bundle index entry same-origin with key-web://<kw-id>.key
                                               │
       response → SetRequiredHeadersForKeyWeb() (KW2) → network service
       ParseHeaders() → renderer. A missing entry gives a synthetic 404 that
       carries the same policy. The loader never falls back to the network.
```

- **No install ceremony.** Nothing is registered, allow-listed or prompted. Any file at `<profile>/Key Web Bundles/<kw-id>.swbn` is a candidate release, and it serves only if it verifies. A resolver, a download, or the user can place it there. The file name comes from the validated base32 ID and never from request input.
- **Factory scoping.**
  - Navigation and service-worker factories are origin-agnostic, because the URL picks the bundle.
  - Subresource and worker factories are registered **only for key-web initiators**, and are locked to that initiator's key (`ERR_BLOCKED_BY_CLIENT` otherwise).
- **Storage.** `GetStoragePartitionConfigForSite()` gives every key its own persistent `StoragePartition`. A hijacked name that resolves to a different key can never reach the original key's data.

## Deliberate deviations and known gaps

| Item | Status |
|---|---|
| `connect-src 'none'` | The patch enforces the exact directive set requested for this prototype. Spec §2.3 normatively uses `connect-src 'self' data: blob:`, because `'self'` is the non-network bundle and `'none'` breaks `fetch('./data.json')`. To switch, change the one constant in `header_policy.cc` (`kKeyWebCsp`). L2 keeps egress closed either way. |
| NG3 static links (`external_links`) | Not implemented. It needs the signed manifest from the release store. Every gestured outbound link takes the prompt, which is stricter than the spec. |
| `keyWeb` decoding | Uses `//components/cbor` in the browser process, with a nesting limit of 8. Production should move this into the memory-safe Rust integrity-block parser (Blueprint KW2, item 1) to keep the Rule of 2. |
| HWM / rollback store, K-SAID KEL, freshness | Not included (Spec §1.6, §4). The cache re-verifies when the file changes but does not enforce monotonic `(kelSn, seq)`. The [`../resolver/`](../resolver/) engine implements the pinning and KERI-rotation logic in JS. |
| Name hosts (`cool-site.alice.example`) | Rejected by the loader (`ERR_INVALID_URL`). Resolution, redirect and display are Blueprint KW6. The JS resolver is the reference model. |
| Push, Background Sync, remote TTS | Not covered by these patches (Spec §2.7, bullet list). |
| Prompt strings | Literal `u""` strings. They need to move to `generated_resources.grd`. |

## Tests added

| Binary | Filter |
|---|---|
| `components_unittests` | `KeyWebOriginTest.*` (KW1), `KeyWebBundleValidationTest.*`, `KeyWebUrlRewriteTest.*` (KW3) |
| `unit_tests` | `KeyWebNavigationPolicyTest.*`, `KeyWebHeaderPolicyTest.*` (KW2) |

The browser tests listed in Blueprint §4 have not been written yet. `NotIsolatedContext`, `PreconnectBlockedAtNetworkService` and the `KeyWebNavigationBrowserTest.*` suite are the next step once the series compiles.
