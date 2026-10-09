#!/usr/bin/env bash
# Upload the trivy SARIF reports of release-scan.sh to GitHub code
# scanning, one analysis per image and architecture (the category is
# "trivy/<image>-<arch>"), through the REST API so several files of the
# same tool do not collide. Needs GH_TOKEN with security-events: write,
# GITHUB_REPOSITORY, GITHUB_SHA and GITHUB_REF. Failures are warnings: the
# reports are also kept as workflow artifacts and release assets.
#
#   scripts/release-sarif.sh OUT
set -uo pipefail
OUT="${1:?usage: release-sarif.sh OUT}"
for f in "$OUT"/scan/*.trivy.sarif; do
  [ -f "$f" ] || continue
  base="$(basename "$f" .trivy.sarif)"
  sarif="$(jq --arg id "trivy/$base/" '.runs |= map(.automationDetails = {id: $id})' "$f" | gzip -c | base64 -w0)" || {
    echo "::warning::$base: could not prepare the SARIF report"
    continue
  }
  if jq -n --arg c "$GITHUB_SHA" --arg r "$GITHUB_REF" --arg s "$sarif" '{commit_sha: $c, ref: $r, sarif: $s}' |
    gh api -X POST "repos/$GITHUB_REPOSITORY/code-scanning/sarifs" --input - >/dev/null; then
    echo "release-sarif: $base uploaded"
  else
    echo "::warning::$base: SARIF upload to code scanning failed"
  fi
done
