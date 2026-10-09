#!/usr/bin/env bash
# Scan the five images and write their SBOMs (release workflow, one run per
# architecture). For each image <prefix><name>:<tag>:
#
#   OUT/sbom/<name>-<arch>.cdx.json        CycloneDX 1.6 (syft)
#   OUT/scan/<name>-<arch>.trivy.json      vulnerabilities and secrets (trivy)
#   OUT/scan/<name>-<arch>.trivy.sarif     the same for GitHub code scanning
#   OUT/scan/<name>-<arch>.grype.json      vulnerabilities (grype)
#   OUT/scan/<name>-<arch>.config.json     image configuration checks (trivy, report only)
#
# Gate (exit 1 after every image is scanned): any Critical or High
# vulnerability with a fix available (trivy or grype), or any secret found
# by trivy. Unfixed findings are reported, not gating. Exceptions only
# through OpenVEX documents in vex/ (each with a justification), which both
# scanners read.
#
#   scripts/release-scan.sh TAG ARCH OUT [IMAGE_PREFIX]   (tools on PATH: scripts/release-tools.sh)
set -euo pipefail
TAG="${1:?usage: release-scan.sh TAG ARCH OUT [IMAGE_PREFIX]}"
ARCH="${2:?arch}"
OUT="${3:?out dir}"
PREFIX="${4:-}"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p "$OUT/sbom" "$OUT/scan"

vex_trivy=() vex_grype=()
for f in vex/*.json; do
  [ -f "$f" ] || continue
  vex_trivy+=(--vex "$f")
  vex_grype+=(--vex "$f")
done

failed=()
for name in samba-conductor-dc samba-conductor samba-conductor-idp samba-conductor-sync samba-conductor-backup; do
  ref="$PREFIX$name:$TAG"
  base="$name-$ARCH"
  echo "== $ref" >&2

  syft scan "docker:$ref" --quiet -o "cyclonedx-json@1.6=$OUT/sbom/$base.cdx.json"

  # One trivy run for the reports (everything, gate off), one for the gate.
  trivy image --quiet --image-src docker --scanners vuln,secret "${vex_trivy[@]}" \
    --format json --output "$OUT/scan/$base.trivy.json" "$ref"
  trivy convert --quiet --format sarif --output "$OUT/scan/$base.trivy.sarif" "$OUT/scan/$base.trivy.json"
  if ! trivy image --quiet --image-src docker --skip-db-update --scanners vuln --ignore-unfixed \
    --severity HIGH,CRITICAL --exit-code 1 "${vex_trivy[@]}" --format table "$ref"; then
    failed+=("$name: trivy, fixable High/Critical")
  fi
  if ! trivy image --quiet --image-src docker --skip-db-update --scanners secret --exit-code 1 \
    --format table "$ref"; then
    failed+=("$name: trivy, secret")
  fi
  trivy image --quiet --image-src docker --skip-db-update --scanners misconfig --image-config-scanners misconfig \
    --format json --output "$OUT/scan/$base.config.json" "$ref" || true

  grype "docker:$ref" --quiet "${vex_grype[@]}" -o "json=$OUT/scan/$base.grype.json"
  grype "docker:$ref" --quiet "${vex_grype[@]}" -o table --only-fixed --fail-on high ||
    failed+=("$name: grype, fixable High/Critical")
done

if [ "${#failed[@]}" -gt 0 ]; then
  printf 'release-scan: gate failed:\n' >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "release-scan: gate passed ($ARCH)"
