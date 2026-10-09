#!/usr/bin/env bash
# The "# syntax=" line of images/Containerfile must name the BuildKit
# frontend pinned by digest in versions.env (DOCKERFILE_FRONTEND): the
# frontend parses the Containerfile, so an unpinned tag would be the one
# build input resolved at build time. Run by make check (CI).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck disable=SC1091
. ./versions.env
case "$DOCKERFILE_FRONTEND" in
*@sha256:????????????????????????????????????????????????????????????????) ;;
*)
  echo "check-frontend-pin: DOCKERFILE_FRONTEND=$DOCKERFILE_FRONTEND is not pinned by a sha256 digest" >&2
  exit 1
  ;;
esac
line="$(head -n 1 images/Containerfile)"
if [ "$line" != "# syntax=$DOCKERFILE_FRONTEND" ]; then
  echo "check-frontend-pin: images/Containerfile starts with \"$line\", want \"# syntax=$DOCKERFILE_FRONTEND\"" >&2
  exit 1
fi
echo "check-frontend-pin: Containerfile frontend pinned to $DOCKERFILE_FRONTEND"
