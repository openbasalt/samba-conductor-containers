#!/usr/bin/env bash
# Release metadata of the container images (release workflow).
#
#   scripts/release-meta.sh plan
#       Decides whether this run may publish and checks the inputs.
#       Publishing needs a push of a tag vX.Y.Z or vX.Y.Z-rc.N whose
#       version equals IMAGE_VERSION in versions.env, and released
#       component packages (no "+git" snapshot versions). Anything else
#       (workflow_dispatch, a branch) is a dry run: build, test and scan,
#       never push. Writes publish=, image_version= and dry_run_reasons=
#       to $GITHUB_OUTPUT when set, and a summary to stdout.
#
#   scripts/release-meta.sh tags LOCAL_TAG [IMAGE_PREFIX]
#       Prints "<image> <immutable tag>" for the five images built as
#       <prefix><image>:LOCAL_TAG. Immutable tags (never overwritten):
#         samba-conductor-dc       <conductor>-samba<samba>-r<N>
#         samba-conductor          <conductor>-r<N>
#         samba-conductor-idp/-sync/-backup   <component>-r<N>
#       where <component> is the package version without the Debian
#       revision ("~rc.1" becomes "-rc.1"), <samba> the upstream Samba
#       version in the DC image and N is IMAGE_REVISION.
#
# The only moving tag this workflow sets is "testing" (preview channel);
# promotion to version and "latest" tags is a separate, later decision.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck disable=SC1091
. ./versions.env

# Docker tag form of a Debian package version: drop the Debian revision,
# "~" -> "-", "+" -> "-" (only snapshot versions have "+", and those never
# publish).
tag_version() {
  local v="${1%-*}"
  v="${v//\~/-}"
  printf '%s' "${v//+/-}"
}

case "${1:-}" in
plan)
  reasons=()
  event="${GITHUB_EVENT_NAME:-local}" ref_type="${GITHUB_REF_TYPE:-}" ref="${GITHUB_REF_NAME:-}"
  version="$IMAGE_VERSION"
  if [ "$event" = push ] && [ "$ref_type" = tag ]; then
    [[ "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "release-meta: tag $ref is not vX.Y.Z or vX.Y.Z-rc.N" >&2; exit 1; }
    [ "${ref#v}" = "$IMAGE_VERSION" ] || { echo "release-meta: tag $ref but IMAGE_VERSION=$IMAGE_VERSION in versions.env" >&2; exit 1; }
    for var in CONDUCTOR_VERSION IDP_VERSION SYNC_VERSION BACKUP_VERSION; do
      v="${!var}"
      [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(~rc\.[0-9]+)?-[0-9]+$ ]] ||
        { echo "release-meta: $var=$v is not a released package version (X.Y.Z-N or X.Y.Z~rc.N-N)" >&2; exit 1; }
    done
    publish=true
  else
    publish=false
    reasons+=("not a tag push ($event${ref:+ of $ref}): dry run")
    for var in CONDUCTOR_VERSION IDP_VERSION SYNC_VERSION BACKUP_VERSION; do
      v="${!var}"
      [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(~rc\.[0-9]+)?-[0-9]+$ ]] ||
        reasons+=("$var=$v is a snapshot, not a released package: a tag run would refuse it")
    done
    version="$IMAGE_VERSION-dryrun"
  fi
  {
    echo "## Container release plan"
    echo
    echo "- publish: **$publish**"
    echo "- image version: \`$version\` (revision r$IMAGE_REVISION)"
    echo "- packages: conductor \`$CONDUCTOR_VERSION\`, conductor-idp \`$IDP_VERSION\`, conductor-sync \`$SYNC_VERSION\`, conductor-backup \`$BACKUP_VERSION\` from $APT_URL ($APT_SUITE)"
    echo "- Debian snapshot: \`$DEBIAN_SNAPSHOT\`"
    for r in "${reasons[@]}"; do echo "- $r"; done
  }
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "publish=$publish"
      echo "image_version=$version"
    } >>"$GITHUB_OUTPUT"
  fi
  ;;
tags)
  local_tag="${2:?usage: release-meta.sh tags LOCAL_TAG [IMAGE_PREFIX]}"
  prefix="${3:-}"
  samba="$(docker run --rm --entrypoint cat "${prefix}samba-conductor-dc:$local_tag" /usr/share/samba-conductor/image.env |
    sed -n 's/^SAMBA_VERSION=//p')"
  samba="${samba#*:}"
  samba="${samba%%[+-]*}"
  [[ "$samba" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-meta: cannot read the Samba version of the DC image ($samba)" >&2; exit 1; }
  r="r$IMAGE_REVISION"
  c="$(tag_version "$CONDUCTOR_VERSION")"
  echo "samba-conductor-dc $c-samba$samba-$r"
  echo "samba-conductor $c-$r"
  echo "samba-conductor-idp $(tag_version "$IDP_VERSION")-$r"
  echo "samba-conductor-sync $(tag_version "$SYNC_VERSION")-$r"
  echo "samba-conductor-backup $(tag_version "$BACKUP_VERSION")-$r"
  ;;
*)
  echo "usage: release-meta.sh plan | tags LOCAL_TAG [IMAGE_PREFIX]" >&2
  exit 2
  ;;
esac
