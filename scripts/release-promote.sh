#!/usr/bin/env bash
# Promotion of a validated containers release to the version tags and
# "latest" (promote workflow, protected container-publish environment).
# The caller is logged in to both registries.
#
#   scripts/release-promote.sh VERSION IMAGES_TXT RESULT
#
# VERSION is a released containers version X.Y.Z (the tag vX.Y.Z; release
# candidates stay on "testing"). IMAGES_TXT is the IMAGES.txt of that
# release ("<registry>/<image>:<immutable tag>@<digest>"). For each image
# and each public registry (docker.io/openbasalt, ghcr.io/openbasalt):
#
# 1. the immutable tag still names the released digest, the digest carries
#    the image version label VERSION, and its signature verifies against
#    the release workflow's identity on the tag vVERSION;
# 2. refusals: a version tag X.Y.Z that names another digest (version tags
#    are never moved once set), and a "latest" that names a newer release
#    (no accidental downgrade of "latest");
# 3. the same digest is tagged X.Y.Z, X.Y, X and "latest" (the DC image
#    also "samba<major.minor>", its Samba line), every tag is read back and
#    must name the released digest (a copy never rebuilds an image);
# 4. the digest is signed again with cosign (keyless, the promote
#    workflow's identity, annotated with the release and the channel) and
#    that signature is verified.
#
# Immutable tags are only read, never written. Writes RESULT/PROMOTED.txt
# ("<registry>/<image>:<tag>@<digest>"). NO_SIGN=1 skips cosign: only for
# a local test against a throwaway registry.
set -euo pipefail
REGISTRIES="${REGISTRIES:-docker.io/openbasalt ghcr.io/openbasalt}"
REPO="${GITHUB_REPOSITORY:-openbasalt/samba-conductor-containers}"
ISSUER=https://token.actions.githubusercontent.com

die() { echo "release-promote: $*" >&2; exit 1; }
digest_of() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r .digest; }
exists() { docker buildx imagetools inspect "$1" >/dev/null 2>&1; }
# version_label REF: the org.opencontainers.image.version label of an
# image or of the first platform of an index.
version_label() {
  docker buildx imagetools inspect "$1" --format '{{json .Image}}' |
    jq -r 'if has("config") then .config.Labels else ([.[]][0].config.Labels) end
      | .["org.opencontainers.image.version"] // empty'
}
cosign() {
  if [ "${NO_SIGN:-}" = 1 ]; then echo "release-promote: NO_SIGN, skipped: cosign $*" >&2; else command cosign "$@"; fi
}

version="${1:?usage: release-promote.sh VERSION IMAGES_TXT RESULT}"
images="${2:?usage: release-promote.sh VERSION IMAGES_TXT RESULT}"
res="${3:?usage: release-promote.sh VERSION IMAGES_TXT RESULT}"
[[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] ||
  die "$version is not X.Y.Z (release candidates are not promoted)"
major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
[ -s "$images" ] || die "$images is missing or empty"
release_id="^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v${version//./\\.}\$"
promote_id="^https://github.com/${REPO}/\.github/workflows/promote\.yml@refs/tags/v${version//./\\.}\$"
mkdir -p "$res"
: >"$res/PROMOTED.txt"

# One line per image from the first registry's entries (the reference
# list); every image must be in every registry with the same immutable tag
# and digest, which step 1 checks.
ref_reg="${REGISTRIES%% *}"
mapfile -t lines < <(awk -v p="$ref_reg/" 'index($0, p) == 1' "$images")
[ "${#lines[@]}" -eq 5 ] || die "$images lists ${#lines[@]} images in $ref_reg, want 5"

for line in "${lines[@]}"; do
  rest="${line#"$ref_reg/"}"
  [ "$rest" != "$line" ] || die "unexpected line in $images: $line"
  [[ "$rest" =~ ^([a-z-]+):([0-9A-Za-z.-]+)@(sha256:[0-9a-f]{64})$ ]] ||
    die "unexpected line in $images: $line"
  img="${BASH_REMATCH[1]}" tag="${BASH_REMATCH[2]}" d="${BASH_REMATCH[3]}"
  [[ "$tag" =~ -r[0-9]+$ ]] || die "$img:$tag is not an immutable tag"
  [[ "$tag" == *-rc.* ]] && die "$img:$tag is a release candidate"
  moving=("$version" "$minor" "$major" latest)
  if [ "$img" = samba-conductor-dc ]; then
    [[ "$tag" =~ -samba([0-9]+\.[0-9]+)\.[0-9]+-r[0-9]+$ ]] || die "$img:$tag names no Samba version"
    moving+=("samba${BASH_REMATCH[1]}")
  fi

  for reg in $REGISTRIES; do
    dst="$reg/$img"
    # 1. The released digest, unchanged, of this release, signed by it.
    [ "$(digest_of "$dst:$tag")" = "$d" ] || die "$dst:$tag does not name the released digest $d"
    [ "$(version_label "$dst@$d")" = "$version" ] || die "$dst@$d is not image version $version"
    cosign verify "$dst@$d" --certificate-oidc-issuer "$ISSUER" --certificate-identity-regexp "$release_id" >/dev/null
    # 2. Refusals.
    if exists "$dst:$version"; then
      cur="$(digest_of "$dst:$version")"
      [ "$cur" = "$d" ] || die "$dst:$version already names $cur: version tags are never moved"
    fi
    if exists "$dst:latest"; then
      cur="$(version_label "$dst:latest")"
      if [ -n "$cur" ] && [ "$cur" != "$version" ] &&
        [ "$(printf '%s\n%s\n' "$cur" "$version" | sort -V | tail -1)" = "$cur" ]; then
        die "$dst:latest is version $cur, newer than $version: refusing to move latest back"
      fi
    fi
    # 3. The moving tags, on the same digest.
    targs=()
    for t in "${moving[@]}"; do targs+=(--tag "$dst:$t"); done
    docker buildx imagetools create "${targs[@]}" "$dst@$d"
    for t in "${moving[@]}"; do
      [ "$(digest_of "$dst:$t")" = "$d" ] || die "$dst:$t: the digest changed in the copy"
      echo "$dst:$t@$d" >>"$res/PROMOTED.txt"
    done
    # 4. The promotion's own signature.
    cosign sign --yes -a "release=v$version" -a channel=latest "$dst@$d"
    cosign verify "$dst@$d" --certificate-oidc-issuer "$ISSUER" --certificate-identity-regexp "$promote_id" >/dev/null
    echo "release-promote: $dst@$d tagged ${moving[*]}"
  done
done
