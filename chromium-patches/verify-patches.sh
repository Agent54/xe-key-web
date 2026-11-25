#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 The Key-Origin Web Authors
#
# Verifies the key-web patch series against a Chromium 160.0.8176.0 tree.
#
#   ./verify-patches.sh <chromium-src-dir>
#
# 1. Each patch must dry-run cleanly against the PRISTINE tree:
#    0 rejects, 0 fuzz, 0 offsets.
# 2. The series KW1 -> KW2 -> KW3 must stack: it is applied to a scratch copy
#    of only the touched files with `git apply` (which never uses fuzz).
# The source tree itself is never modified.
set -eu

SRC=${1:?usage: verify-patches.sh <chromium-src-dir>}
HERE=$(cd "$(dirname "$0")" && pwd)
SERIES="KW1-register-key-web-unprivileged-scheme.patch
KW2-key-web-exfiltration-proof-csp-and-navigation-throttle.patch
KW3-key-web-signed-bundle-url-loader-factory.patch"

if [ "$(sed -n 's/^MAJOR=//p' "$SRC/chrome/VERSION" 2>/dev/null)" != "160" ]; then
  echo "warning: $SRC/chrome/VERSION is not MAJOR=160" >&2
fi

status=0
for p in $SERIES; do
  out=$(patch --dry-run -p1 -d "$SRC" < "$HERE/$p" 2>&1) || status=1
  files=$(printf '%s\n' "$out" | grep -c '^patching file' || true)
  bad=$(printf '%s\n' "$out" | grep -ciE 'fuzz|offset|reject|fail|malformed' || true)
  if [ "$bad" -eq 0 ] && [ "$status" -eq 0 ]; then
    echo "PASS  $p  ($files files, 0 rejects, 0 fuzz, 0 offsets)"
  else
    echo "FAIL  $p"; printf '%s\n' "$out"; status=1
  fi
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for p in $SERIES; do
  sed -n 's#^+++ b/##p' "$HERE/$p"
done | sort -u | while read -r f; do
  if [ -f "$SRC/$f" ]; then
    mkdir -p "$WORK/$(dirname "$f")"
    cp "$SRC/$f" "$WORK/$f"
  fi
done
(
  cd "$WORK"
  git init -q .
  for p in $SERIES; do
    git apply "$HERE/$p"
  done
) && echo "PASS  series KW1 -> KW2 -> KW3 stacks with git apply (no fuzz)" \
  || { echo "FAIL  series does not stack"; status=1; }

exit $status
