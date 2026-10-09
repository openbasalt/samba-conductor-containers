#!/usr/bin/env bash
# The compose files' default image tag (${SC_TAG:-...}) and SC_TAG in
# compose/.env.example must be IMAGE_VERSION of versions.env: a compose
# checkout of a release then runs that release's images, never "latest"
# by surprise. Run by make check (CI) and by the release plan.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck disable=SC1091
. ./versions.env
bad=0
while IFS= read -r hit; do
  file="${hit%%:*}" tag="${hit##*SC_TAG:-}" tag="${tag%%\}*}"
  if [ "$tag" != "$IMAGE_VERSION" ]; then
    echo "check-compose-tag: $file defaults SC_TAG to $tag, want IMAGE_VERSION=$IMAGE_VERSION" >&2
    bad=1
  fi
done < <(grep -o 'SC_TAG:-[^}]*}' -r compose --include='*.yaml' -H)
env_tag="$(sed -n 's/^SC_TAG=//p' compose/.env.example)"
if [ "$env_tag" != "$IMAGE_VERSION" ]; then
  echo "check-compose-tag: compose/.env.example sets SC_TAG=$env_tag, want IMAGE_VERSION=$IMAGE_VERSION" >&2
  bad=1
fi
[ "$bad" = 0 ] && echo "check-compose-tag: compose files default to $IMAGE_VERSION"
exit "$bad"
