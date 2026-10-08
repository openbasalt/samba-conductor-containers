#!/usr/bin/env bash
# Build the images locally (never pushed): one target per image of
# images/Containerfile, tagged <name>:<tag>.
#
#   ./build-local.sh [--source apt|local] [--debs DIR] [--tag TAG]
#                    [--platform linux/amd64|linux/arm64] [--output load|none]
#                    [--image-version V] [dc conductor idp sync backup]
#
# --source apt (default): the component packages pinned in versions.env,
#   from the OpenBasalt APT repository, verified through its signed InRelease.
# --source local: packages built locally (make package in each component; lab
#   builds) in DIR, checked against DIR/SHA256SUMS (and DIR/SHA256SUMS.asc
#   when DIR/keyring.gpg is there); the newest of each name is used.
# --output none builds without loading the result (an architecture check).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
SOURCE=apt DEBS="" TAG=dev PLATFORM="" OUTPUT=load IMAGE_VERSION_ARG=""
TARGETS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
  --source) SOURCE="$2"; shift 2 ;;
  --debs) DEBS="$2"; shift 2 ;;
  --tag) TAG="$2"; shift 2 ;;
  --platform) PLATFORM="$2"; shift 2 ;;
  --output) OUTPUT="$2"; shift 2 ;;
  --image-version) IMAGE_VERSION_ARG="$2"; shift 2 ;;
  -h | --help) sed -n '2,16p' "$0"; exit 0 ;;
  -*) echo "build-local.sh: unknown option $1" >&2; exit 2 ;;
  *) TARGETS+=("$1"); shift ;;
  esac
done
[ "${#TARGETS[@]}" -gt 0 ] || TARGETS=(dc conductor idp sync backup)
# shellcheck disable=SC1091
. ./versions.env
[ -n "$IMAGE_VERSION_ARG" ] && IMAGE_VERSION="$IMAGE_VERSION_ARG"

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
args=(--build-arg "IMAGE_VERSION=$IMAGE_VERSION" --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT"
  --build-arg "DEBIAN_IMAGE=$DEBIAN_IMAGE" --build-arg "DISTROLESS_IMAGE=$DISTROLESS_IMAGE" --build-arg "GO_IMAGE=$GO_IMAGE"
  --build-arg "SC_SOURCE=$SOURCE")
case "$SOURCE" in
apt)
  args+=(--build-arg "APT_URL=$APT_URL" --build-arg "APT_SUITE=$APT_SUITE"
    --build-arg "CONDUCTOR_VERSION=$CONDUCTOR_VERSION" --build-arg "IDP_VERSION=$IDP_VERSION"
    --build-arg "SYNC_VERSION=$SYNC_VERSION" --build-arg "BACKUP_VERSION=$BACKUP_VERSION")
  ;;
local)
  [ -n "$DEBS" ] && [ -f "$DEBS/SHA256SUMS" ] || { echo "build-local.sh: --source local needs --debs DIR with SHA256SUMS" >&2; exit 2; }
  # Only what the images need: the amd64/arm64 .debs of the four components.
  for f in "$DEBS"/SHA256SUMS "$DEBS"/SHA256SUMS.asc "$DEBS"/keyring.gpg; do [ -f "$f" ] && cp "$f" "$ctx/"; done
  for p in conductor conductor-idp conductor-sync conductor-backup; do
    for a in amd64 arm64; do
      newest="$(ls -1 "$DEBS"/"${p}"_*_"$a".deb 2>/dev/null | sort -V | tail -1 || true)"
      [ -n "$newest" ] && cp "$newest" "$ctx/"
    done
  done
  ;;
*) echo "build-local.sh: --source apt or local" >&2; exit 2 ;;
esac
[ -n "$PLATFORM" ] && args+=(--platform "$PLATFORM")
case "$OUTPUT" in
load) args+=(--load) ;;
none) ;;
*) echo "build-local.sh: --output load or none" >&2; exit 2 ;;
esac
# Reproducible metadata: the commit time of this repository.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
export SOURCE_DATE_EPOCH
declare -A NAME=([dc]=samba-conductor-dc [conductor]=samba-conductor [idp]=samba-conductor-idp
  [sync]=samba-conductor-sync [backup]=samba-conductor-backup)
for t in "${TARGETS[@]}"; do
  [ -n "${NAME[$t]:-}" ] || { echo "build-local.sh: unknown target $t" >&2; exit 2; }
  echo "== ${NAME[$t]}:$TAG ($SOURCE${PLATFORM:+, $PLATFORM})" >&2
  docker buildx build "${args[@]}" --build-context "debs=$ctx" --target "$t" \
    --provenance=false --sbom=false -f images/Containerfile -t "${NAME[$t]}:$TAG" .
done
