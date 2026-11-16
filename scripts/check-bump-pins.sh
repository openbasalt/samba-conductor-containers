#!/usr/bin/env bash
# Test of scripts/bump-pins.sh (make check): on a copy of versions.env it
# moves DEBIAN_SNAPSHOT forward, leaves every other line alone and refuses
# a snapshot older than the pinned one or a malformed one. Offline: no
# registry or snapshot.debian.org access.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "check-bump-pins: FAIL: $*" >&2; exit 1; }

cp versions.env "$tmp/v.env"
out="$(scripts/bump-pins.sh --file "$tmp/v.env" --snapshot 29991231T000000Z --no-digests --no-verify)"
grep -q '^DEBIAN_SNAPSHOT: .* -> 29991231T000000Z$' <<<"$out" || fail "no change reported"
[ "$(grep -c '^DEBIAN_SNAPSHOT=29991231T000000Z$' "$tmp/v.env")" = 1 ] || fail "DEBIAN_SNAPSHOT not set"
# Only that line differs.
[ "$(diff versions.env "$tmp/v.env" | grep -c '^[<>]')" = 2 ] || fail "other lines changed"
# Idempotent.
[ -z "$(scripts/bump-pins.sh --file "$tmp/v.env" --snapshot 29991231T000000Z --no-digests --no-verify)" ] ||
  fail "a second run reported a change"
# Never backwards, never malformed.
if scripts/bump-pins.sh --file "$tmp/v.env" --snapshot 20000101T000000Z --no-digests --no-verify 2>/dev/null; then
  fail "an older snapshot was accepted"
fi
if scripts/bump-pins.sh --file "$tmp/v.env" --snapshot 'latest' --no-digests --no-verify 2>/dev/null; then
  fail "a floating snapshot was accepted"
fi
echo "check-bump-pins: ok"
