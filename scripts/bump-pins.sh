#!/usr/bin/env bash
# Advance the Debian inputs pinned in versions.env: DEBIAN_SNAPSHOT to a
# newer snapshot.debian.org timestamp (default: today, 00:00 UTC) and the
# digests of DEBIAN_IMAGE, DISTROLESS_IMAGE and GO_IMAGE to what their tags
# name now. Every value stays a fixed pin (a timestamp, a digest); this only
# moves the pins, by pull request (.github/workflows/bump-pins.yml), so CI
# builds and tests the new inputs before anything uses them.
#
#   scripts/bump-pins.sh [--snapshot YYYYMMDDTHHMMSSZ] [--no-digests] [--no-verify] [--file FILE]
#
# --no-digests keeps the image digests (no registry access); --no-verify
# skips the check that the snapshot exists. Prints one line per changed pin
# ("KEY: old -> new"); exits 0 also when nothing changed. A snapshot older
# than the pinned one is refused (pins only move forward).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
FILE=versions.env SNAPSHOT="" DIGESTS=1 VERIFY=1
while [ "$#" -gt 0 ]; do
  case "$1" in
  --snapshot) SNAPSHOT="$2"; shift 2 ;;
  --no-digests) DIGESTS=0; shift ;;
  --no-verify) VERIFY=0; shift ;;
  --file) FILE="$2"; shift 2 ;;
  -h | --help) sed -n '2,15p' "$0"; exit 0 ;;
  *) echo "bump-pins.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$SNAPSHOT" ] || SNAPSHOT="$(date -u +%Y%m%dT000000Z)"
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "bump-pins.sh: snapshot $SNAPSHOT is not YYYYMMDDTHHMMSSZ" >&2; exit 2; }
[ -f "$FILE" ] || { echo "bump-pins.sh: $FILE not found" >&2; exit 2; }

# get KEY: the value of KEY= in FILE (exactly one line).
get() {
  local n
  n="$(grep -c "^$1=" "$FILE" || true)"
  [ "$n" = 1 ] || { echo "bump-pins.sh: $1 must appear once in $FILE (found $n)" >&2; exit 1; }
  sed -n "s/^$1=//p" "$FILE"
}
# set KEY OLD NEW: replace the value of KEY and report the change.
set_pin() {
  [ "$2" = "$3" ] && return 0
  local tmp
  tmp="$(mktemp "$FILE.XXXXXX")"
  awk -v k="$1" -v v="$3" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$FILE" >"$tmp"
  chmod --reference="$FILE" "$tmp" 2>/dev/null || true
  mv "$tmp" "$FILE"
  echo "$1: $2 -> $3"
}

old="$(get DEBIAN_SNAPSHOT)"
[[ "$old" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "bump-pins.sh: DEBIAN_SNAPSHOT=$old is not a timestamp" >&2; exit 1; }
if [[ "$SNAPSHOT" < "$old" ]]; then
  echo "bump-pins.sh: $SNAPSHOT is older than the pinned $old" >&2
  exit 1
fi
if [ "$VERIFY" = 1 ] && [ "$SNAPSHOT" != "$old" ]; then
  # The signed InRelease of every suite the images use must be there
  # (apt verifies the signatures at build time).
  for s in debian/dists/trixie debian/dists/trixie-updates debian-security/dists/trixie-security; do
    url="https://snapshot.debian.org/archive/${s%%/*}/$SNAPSHOT/${s#*/}/InRelease"
    curl -fsSL --retry 3 -o /dev/null "$url" || { echo "bump-pins.sh: $url is not available" >&2; exit 1; }
  done
fi
set_pin DEBIAN_SNAPSHOT "$old" "$SNAPSHOT"

if [ "$DIGESTS" = 1 ]; then
  for key in DEBIAN_IMAGE DISTROLESS_IMAGE GO_IMAGE; do
    cur="$(get "$key")"
    [[ "$cur" =~ ^([a-z0-9./_-]+:[A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})$ ]] ||
      { echo "bump-pins.sh: $key=$cur is not <image>:<tag>@sha256:<digest>" >&2; exit 1; }
    ref="${BASH_REMATCH[1]}"
    digest="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' | jq -r .digest)"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "bump-pins.sh: no digest for $ref" >&2; exit 1; }
    set_pin "$key" "$cur" "$ref@$digest"
  done
fi
