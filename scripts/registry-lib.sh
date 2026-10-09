# shellcheck shell=bash
# Registry helpers shared by scripts/release-publish.sh and
# scripts/release-promote.sh (sourced, not run). The caller defines die().
#
# Registries answer late or not at all now and then: Docker Hub lists a new
# cosign signature a few seconds after it was pushed, and returns 429 Too
# Many Requests under load. These helpers retry such failures, and tell a
# registry error apart from an absent tag or a digest mismatch, so a refusal
# is never decided on a failed lookup.

# retry TRIES DELAY CMD...: run CMD until it succeeds, at most TRIES times,
# waiting DELAY seconds after the first failure, 2*DELAY after the second
# and so on. Returns the status of the last attempt.
retry() {
  # Prefixed locals: bash scoping is dynamic and CMD may be a function.
  local _r_tries="$1" _r_delay="$2" _r_n=1 _r_rc
  shift 2
  while :; do
    _r_rc=0
    "$@" || _r_rc=$?
    [ "$_r_rc" -eq 0 ] && return 0
    [ "$_r_n" -ge "$_r_tries" ] && return "$_r_rc"
    echo "retry: attempt $_r_n of $_r_tries failed (status $_r_rc), next in $((_r_delay * _r_n))s: $1 ${2:-}" >&2
    sleep "$((_r_delay * _r_n))"
    _r_n=$((_r_n + 1))
  done
}

# Attempts and base delay of a registry lookup (the delay grows as in retry).
REGISTRY_TRIES="${REGISTRY_TRIES:-6}"
REGISTRY_DELAY="${REGISTRY_DELAY:-5}"

# registry_inspect REF [ARGS...]: docker buildx imagetools inspect REF ARGS,
# its output on stdout. Status 0 on success, 2 when the registry says the
# tag or repository does not exist (not retried), 1 when every attempt
# failed for another reason (429, 5xx, network, auth; the error output is
# kept in REGISTRY_ERRFILE, as lookups run in command substitutions).
# Errexit is not relied on: callers use it in conditions.
registry_inspect() {
  local ref="$1" n=1 out err
  shift
  while :; do
    if out="$(docker buildx imagetools inspect "$ref" "$@" 2>"$REGISTRY_ERRFILE")"; then
      printf '%s\n' "$out"
      return 0
    fi
    err="$(tr '\n' ' ' <"$REGISTRY_ERRFILE")"
    # Only an explicit answer from the registry counts as absent.
    if grep -qiE '(^|[^a-z])(not found|manifest unknown|name unknown)' <<<"$err"; then
      return 2
    fi
    [ "$n" -ge "$REGISTRY_TRIES" ] && return 1
    echo "registry: lookup of $ref failed (attempt $n of $REGISTRY_TRIES), next in $((REGISTRY_DELAY * n))s: $err" >&2
    sleep "$((REGISTRY_DELAY * n))"
    n=$((n + 1))
  done
}

# registry_fail REF: stop, the registry lookup of REF failed.
registry_fail() { die "registry lookup of $1 failed: $(tr '\n' ' ' <"$REGISTRY_ERRFILE")"; }

# digest_of REF: the digest REF names. Stops on a failed lookup (an absent
# tag included), so callers assign it on its own line and then compare.
digest_of() {
  local out
  out="$(registry_inspect "$1" --format '{{json .Manifest}}')" || registry_fail "$1"
  jq -r .digest <<<"$out"
}

# exists REF: true when REF exists, false only when the registry says it
# does not; any other failure stops (a 429 must never pass for an absent
# tag, which would skip the refusals).
exists() {
  local rc=0
  registry_inspect "$1" >/dev/null || rc=$?
  case "$rc" in
  0) return 0 ;;
  2) return 1 ;;
  *) registry_fail "$1" ;;
  esac
}

# version_label REF: the org.opencontainers.image.version label of an image
# or of the first platform of an index. Stops on a failed lookup.
version_label() {
  local out
  out="$(registry_inspect "$1" --format '{{json .Image}}')" || registry_fail "$1"
  jq -r 'if has("config") then .config.Labels else ([.[]][0].config.Labels) end
    | .["org.opencontainers.image.version"] // empty' <<<"$out"
}

REGISTRY_ERRFILE="$(mktemp)"
trap 'rm -f "$REGISTRY_ERRFILE"' EXIT
