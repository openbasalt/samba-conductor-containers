#!/usr/bin/env bash
# Smoke test of freshly built images (CI and the release workflow): a new
# domain in the DC image on a bridge network, the healthcheck, idempotency
# on recreate (same domain SID, no second provisioning) and the security
# assertions (not privileged, exact capabilities, read-only root, fixed
# users, no secret in any environment). Uses compose/ with a throwaway .env
# and secrets; removes the stack and its volumes at the end.
#
#   scripts/ci-smoke.sh TAG [IMAGE_PREFIX]
set -euo pipefail
TAG="${1:?usage: ci-smoke.sh TAG [IMAGE_PREFIX]}"
PREFIX="${2:-}"
cd "$(dirname "${BASH_SOURCE[0]}")/../compose"

fail() { echo "ci-smoke: FAIL: $*" >&2; exit 1; }
ok() { echo "ci-smoke: ok: $*"; }

# The images' own users (section "Users" of the README): a wrong USER in an
# image would break the SO_PEERCRED checks between containers.
declare -A USERS=([samba-conductor]=2093:2093 [samba-conductor-idp]=2095:2095
  [samba-conductor-sync]=2094:2094 [samba-conductor-backup]=2097:2097)
for img in "${!USERS[@]}"; do
  u="$(docker image inspect -f '{{.Config.User}}' "$PREFIX$img:$TAG")"
  [ "$u" = "${USERS[$img]}" ] || fail "$img runs as '$u', want ${USERS[$img]}"
done
ok "service images run as their fixed UIDs"

ip="$(hostname -I | awk '{print $1}')"
printf 'SC_DNS_DOMAIN=ci.example.test\nSC_NETBIOS=CI\nSC_HOSTNAME=dc1\nSC_HOST_IP=%s\nSC_TAG=%s\nSC_IMAGE_PREFIX=%s\nSC_ALLOW_UNSYNCED_CLOCK=1\n' \
  "$ip" "$TAG" "$PREFIX" >.env
trap 'docker compose logs dc | tail -n 80 || true; docker compose down -v || true; rm -rf .env secrets' EXIT
./make-secrets.sh 2>/dev/null

wait_healthy() {
  local id status
  for _ in $(seq 120); do
    id="$(docker compose ps -q dc)"
    status="$(docker inspect -f '{{.State.Health.Status}}' "$id")"
    [ "$status" = healthy ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$id")" = true ] || fail "the DC container stopped"
    sleep 5
  done
  fail "the DC is not healthy after 10 minutes (last status: $status)"
}
domain_sid() {
  docker compose exec -T dc ldbsearch -H /var/lib/samba/private/sam.ldb -s base \
    -b DC=ci,DC=example,DC=test objectSid | awk '/^objectSid:/{print $2}'
}

docker compose up -d dc
wait_healthy
docker compose exec -T dc sc-dc-init health
[ "$(docker compose logs dc | grep -c 'provisioning CI.EXAMPLE.TEST')" = 1 ] || fail "provisioning not logged once"
sid1="$(domain_sid)"
[ -n "$sid1" ] || fail "no domain SID"
ok "fresh provision, healthy ($sid1)"

# T3: a recreated container runs the domain on the volume and never
# provisions again.
docker compose up -d --force-recreate dc
wait_healthy
docker compose exec -T dc sc-dc-init health
logs="$(docker compose logs dc)"
! grep -q 'provisioning CI.EXAMPLE.TEST' <<<"$logs" || fail "provisioned again after recreate"
grep -q 'SC_MODE=provision ignored' <<<"$logs" || fail "recreate did not report the existing domain"
[ "$(domain_sid)" = "$sid1" ] || fail "domain SID changed after recreate"
ok "recreate keeps the domain"

# T10: security assertions on the running DC.
id="$(docker compose ps -q dc)"
[ "$(docker inspect -f '{{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}}' "$id")" = "false true" ] ||
  fail "privileged or writable root"
caps="$(docker inspect -f '{{range .HostConfig.CapAdd}}{{println .}}{{end}}' "$id" | sed -n 's/^\(CAP_\)\{0,1\}\([A-Z_]\{1,\}\)$/\2/p' | sort | tr '\n' ' ')"
want="CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL NET_BIND_SERVICE SETGID SETUID "
[ "$caps" = "$want" ] || fail "capabilities: '$caps', want '$want'"
grep -qE '^\["(CAP_)?ALL"\]$' <<<"$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$id")" || fail "cap_drop is not ALL"
docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$id" | grep -q 'no-new-privileges:true' || fail "no-new-privileges missing"
# The nine capabilities above as a mask: bits 0-7 and 10.
capeff="$(docker compose exec -T dc cat /proc/1/status | awk '/^CapEff:/{print $2}')"
[ "$capeff" = 00000000000004ff ] || fail "PID 1 CapEff $capeff, want 00000000000004ff"
if docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" | grep -iE '^[^=]*(PASSWORD|SECRET|_KEY|PASS)='; then
  fail "a secret-like variable is in the DC's environment"
fi
ok "not privileged, read-only root, exact capabilities (CapEff $capeff), no secrets in the environment"
