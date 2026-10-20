#!/bin/sh
# Fetch and verify the component packages an image is built from.
#
#   fetch-debs.sh apt   ARCH OUTDIR PKG=VERSION...   (APT_URL, APT_SUITE)
#   fetch-debs.sh local ARCH OUTDIR PKG=VERSION...   (packages in /in)
#
# apt: the published OpenBasalt APT repository. APT_SUITE names one suite
# or several (space-separated, searched in order: each package comes from
# the first suite whose index has that exact version). For each suite,
# InRelease is verified with gpgv against the committed release key
# (keys/openbasalt-release-key.gpg), the Packages index against the
# SHA-256 in InRelease, and each .deb against the SHA-256 in the index:
# the same chain apt itself uses.
#
# local: packages built locally (lab builds, never
# published), checked against their SHA256SUMS; when /in/SHA256SUMS.asc and
# /in/keyring.gpg exist, the sums are verified with gpgv first. VERSION may
# be "*" (the only package of that name in /in).
#
# Each package ends up as OUTDIR/<pkg>.deb and OUTDIR/<pkg>.version.
set -eu
MODE="$1" ARCH="$2" OUT="$3"
shift 3
KEYRING=/keys/openbasalt-release-key.gpg
mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
die() { echo "fetch-debs: $*" >&2; exit 1; }

case "$MODE" in
apt)
  base="${APT_URL:?}"
  suites="${APT_SUITE:-stable}"
  idx="main/binary-$ARCH/Packages"
  # Verify every suite's index first: a package is only ever looked up in
  # a verified index.
  for suite in $suites; do
    case "$suite" in *[!a-z0-9-]* | "") die "APT_SUITE: bad suite name '$suite'" ;; esac
    d="$work/$suite"
    mkdir -p "$d"
    curl -fsSL --retry 3 -o "$d/InRelease" "$base/dists/$suite/InRelease"
    gpgv --keyring "$KEYRING" --output "$d/Release" "$d/InRelease" 2>"$d/gpgv.log" ||
      { cat "$d/gpgv.log" >&2; die "$suite InRelease: bad signature"; }
    grep -q '302461D26520E077D07FFCA9AA27C62C36CCFC4B\|AA27C62C36CCFC4B' "$d/gpgv.log" ||
      { cat "$d/gpgv.log" >&2; die "$suite InRelease is not signed by the OpenBasalt packages subkey"; }
    want="$(awk -v f="$idx" '/^SHA256:/{s=1;next} /^[^ ]/{s=0} s && $3==f {print $1}' "$d/Release")"
    [ -n "$want" ] || die "$suite: $idx is not listed in InRelease"
    curl -fsSL --retry 3 -o "$d/Packages" "$base/dists/$suite/$idx"
    echo "$want  $d/Packages" | sha256sum -c --quiet - || die "$suite: $idx: SHA-256 mismatch"
  done
  for spec in "$@"; do
    pkg="${spec%%=*}" ver="${spec#*=}"
    line="" from=""
    for suite in $suites; do
      line="$(awk -v p="$pkg" -v v="$ver" '
        /^Package: /{pk=$2} /^Version: /{vr=$2} /^Filename: /{fn=$2} /^SHA256: /{sh=$2}
        /^$/{ if (pk==p && vr==v) print fn, sh; pk=vr=fn=sh="" }
        END{ if (pk==p && vr==v) print fn, sh }' "$work/$suite/Packages" | head -n 1)"
      [ -n "$line" ] && { from="$suite"; break; }
    done
    [ -n "$line" ] || die "$pkg $ver ($ARCH) is not in $base ($suites)"
    fn="${line% *}" sha="${line#* }"
    curl -fsSL --retry 3 -o "$OUT/$pkg.deb" "$base/$fn"
    echo "$sha  $OUT/$pkg.deb" | sha256sum -c --quiet - || die "$pkg: SHA-256 mismatch"
    printf '%s\n' "$ver" >"$OUT/$pkg.version"
    echo "fetch-debs: $pkg $ver verified ($from: InRelease -> Packages -> .deb)"
  done
  ;;
local)
  [ -f /in/SHA256SUMS ] || die "local: /in/SHA256SUMS missing"
  if [ -f /in/SHA256SUMS.asc ] && [ -f /in/keyring.gpg ]; then
    gpgv --keyring /in/keyring.gpg /in/SHA256SUMS.asc /in/SHA256SUMS || die "local: SHA256SUMS: bad signature"
    echo "fetch-debs: local SHA256SUMS signature verified (lab key)"
  fi
  for spec in "$@"; do
    pkg="${spec%%=*}" ver="${spec#*=}"
    if [ "$ver" = "*" ]; then
      set -- /in/"${pkg}"_*_"$ARCH".deb
      [ "$#" -eq 1 ] && [ -f "$1" ] || die "local: expected exactly one ${pkg}_*_$ARCH.deb in /in"
      f="$1"
    else
      f="/in/${pkg}_${ver}_$ARCH.deb"
      [ -f "$f" ] || die "local: $f missing"
    fi
    name="$(basename "$f")"
    sum="$(awk -v n="$name" '{f=$2; sub(/^\*/, "", f)} f==n {print $1}' /in/SHA256SUMS)"
    [ -n "$sum" ] || die "local: $name is not in SHA256SUMS"
    echo "$sum  $f" | sha256sum -c --quiet - || die "local: $name: SHA-256 mismatch"
    cp "$f" "$OUT/$pkg.deb"
    dpkg-deb -f "$f" Version >"$OUT/$pkg.version"
    echo "fetch-debs: $pkg $(cat "$OUT/$pkg.version") verified (SHA256SUMS)"
  done
  ;;
*) die "unknown mode $MODE" ;;
esac
