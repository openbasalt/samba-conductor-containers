#!/usr/bin/env bash
# Publishing steps of the release workflow (tag runs only; a dry run never
# calls this script). The caller is logged in to the registries.
#
#   push-arch LOCAL_TAG ARCH OUT
#       Push the five images built as <image>:LOCAL_TAG to the staging
#       registry as <immutable tag>-<arch> (tags from OUT/tags.txt) and
#       write "<image> <arch> <digest>" lines to OUT/digests.txt.
#
#   index AMD64_OUT ARM64_OUT RESULT
#       Per image: the multi-arch index in the staging registry under the
#       immutable tag (refused if that tag exists), signed with cosign
#       (keyless) and the per-arch CycloneDX SBOMs attached as cosign
#       attestations. Writes RESULT/staged.txt
#       ("<image> <tag> <index digest> <amd64 digest> <arm64 digest>") and
#       RESULT/staged.json (the attest job's matrix).
#
#   promote RESULT
#       Per image: copy the staged index to the public registry under the
#       immutable tag and "testing" (refused if the immutable tag exists),
#       check the digest did not change, sign and attest there too, verify
#       the signature against this workflow's identity, write
#       RESULT/IMAGES.txt ("<registry>/<image>:<tag>@<digest>").
#
# Registries: STAGING (default ghcr.io/openbasalt) and PUBLIC (default
# docker.io/openbasalt). Never touches "latest" or version tags.
# NO_SIGN=1 skips cosign: only for a local test of the copy steps against a
# throwaway registry (keyless signing needs the workflow's OIDC token).
set -euo pipefail
STAGING="${STAGING:-ghcr.io/openbasalt}"
PUBLIC="${PUBLIC:-docker.io/openbasalt}"
# The identity cosign verify accepts: this repository's release workflow
# on a v* tag.
IDENTITY_RE="^https://github.com/${GITHUB_REPOSITORY:-openbasalt/samba-conductor-containers}/\.github/workflows/release\.yml@refs/tags/v"
ISSUER=https://token.actions.githubusercontent.com

die() { echo "release-publish: $*" >&2; exit 1; }
digest_of() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r .digest; }
exists() { docker buildx imagetools inspect "$1" >/dev/null 2>&1; }
cosign() {
  if [ "${NO_SIGN:-}" = 1 ]; then echo "release-publish: NO_SIGN, skipped: cosign $*" >&2; else command cosign "$@"; fi
}

case "${1:-}" in
push-arch)
  local_tag="${2:?}" arch="${3:?}" out="${4:?}"
  : >"$out/digests.txt"
  while read -r img tag; do
    remote="$STAGING/$img:$tag-$arch"
    docker tag "$img:$local_tag" "$remote"
    docker push --quiet "$remote" >/dev/null
    d="$(digest_of "$remote")"
    [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$remote: no digest"
    echo "$img $arch $d" >>"$out/digests.txt"
    echo "release-publish: $remote@$d"
  done <"$out/tags.txt"
  ;;
index)
  amd="${2:?}" arm="${3:?}" res="${4:?}"
  mkdir -p "$res"
  cmp -s "$amd/tags.txt" "$arm/tags.txt" || die "the architectures disagree on the tags (Samba or package versions differ)"
  : >"$res/staged.txt"
  while read -r img tag; do
    da="$(awk -v i="$img" '$1==i && $2=="amd64" {print $3}' "$amd/digests.txt")"
    dr="$(awk -v i="$img" '$1==i && $2=="arm64" {print $3}' "$arm/digests.txt")"
    [ -n "$da" ] && [ -n "$dr" ] || die "$img: a per-arch digest is missing"
    ref="$STAGING/$img:$tag"
    exists "$ref" && die "$ref already exists: immutable tags are never overwritten (raise IMAGE_REVISION)"
    docker buildx imagetools create --tag "$ref" "$STAGING/$img@$da" "$STAGING/$img@$dr"
    di="$(digest_of "$ref")"
    cosign sign --yes "$STAGING/$img@$di"
    cosign attest --yes --type cyclonedx --predicate "$amd/sbom/$img-amd64.cdx.json" "$STAGING/$img@$da"
    cosign attest --yes --type cyclonedx --predicate "$arm/sbom/$img-arm64.cdx.json" "$STAGING/$img@$dr"
    echo "$img $tag $di $da $dr" >>"$res/staged.txt"
    echo "release-publish: staged $ref@$di"
  done <"$amd/tags.txt"
  jq -R -s -c --arg reg "$STAGING" 'split("\n") | map(select(length > 0) | split(" ")
    | {image: .[0], tag: .[1], name: ($reg + "/" + .[0]), index: .[2], amd64: .[3], arm64: .[4]})' \
    "$res/staged.txt" >"$res/staged.json"
  ;;
promote)
  res="${2:?}" sboms="${3:?usage: promote RESULT SBOM_DIR}"
  : >"$res/IMAGES.txt"
  while read -r img tag di da dr; do
    dst="$PUBLIC/$img"
    exists "$dst:$tag" && die "$dst:$tag already exists: immutable tags are never overwritten"
    docker buildx imagetools create --tag "$dst:$tag" --tag "$dst:testing" "$STAGING/$img@$di"
    [ "$(digest_of "$dst:$tag")" = "$di" ] || die "$dst:$tag: the digest changed in the copy"
    cosign sign --yes "$dst@$di"
    cosign attest --yes --type cyclonedx --predicate "$sboms/$img-amd64.cdx.json" "$dst@$da"
    cosign attest --yes --type cyclonedx --predicate "$sboms/$img-arm64.cdx.json" "$dst@$dr"
    cosign verify "$dst@$di" --certificate-oidc-issuer "$ISSUER" --certificate-identity-regexp "$IDENTITY_RE" >/dev/null
    echo "$dst:$tag@$di" >>"$res/IMAGES.txt"
    echo "release-publish: published $dst:$tag@$di (and :testing)"
  done <"$res/staged.txt"
  ;;
*)
  echo "usage: release-publish.sh push-arch LOCAL_TAG ARCH OUT | index AMD64_OUT ARM64_OUT RESULT | promote RESULT SBOM_DIR" >&2
  exit 2
  ;;
esac
