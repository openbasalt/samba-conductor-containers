#!/usr/bin/env bash
# Install the pinned scanners and SBOM generator of the release workflow
# into DIR (default .tools/release), each download checked against the
# SHA-256 written here (taken from the projects' signed or published
# checksum files when the pin was set; changing a pin is a pull request).
#
#   scripts/release-tools.sh [DIR]
#
# Tools: trivy (vulnerabilities, secrets, image configuration), grype
# (vulnerabilities, second opinion), syft (CycloneDX SBOM), hadolint
# (Containerfile lint), cosign (keyless signatures and attestations).
set -euo pipefail
DIR="${1:-.tools/release}"
TRIVY_VERSION=0.75.0
GRYPE_VERSION=0.119.0
SYFT_VERSION=1.52.0
HADOLINT_VERSION=2.15.1
COSIGN_VERSION=3.1.3

case "$(uname -m)" in
x86_64)
  TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" TRIVY_SHA=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
  GRYPE_ASSET="grype_${GRYPE_VERSION}_linux_amd64.tar.gz" GRYPE_SHA=3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b
  SYFT_ASSET="syft_${SYFT_VERSION}_linux_amd64.tar.gz" SYFT_SHA=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d
  HADOLINT_ASSET=hadolint-linux-x86_64 HADOLINT_SHA=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
  COSIGN_ASSET=cosign-linux-amd64 COSIGN_SHA=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
  ;;
aarch64)
  TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" TRIVY_SHA=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
  GRYPE_ASSET="grype_${GRYPE_VERSION}_linux_arm64.tar.gz" GRYPE_SHA=29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8
  SYFT_ASSET="syft_${SYFT_VERSION}_linux_arm64.tar.gz" SYFT_SHA=c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706
  HADOLINT_ASSET=hadolint-linux-arm64 HADOLINT_SHA=f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d
  COSIGN_ASSET=cosign-linux-arm64 COSIGN_SHA=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a
  ;;
*) echo "release-tools.sh: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# fetch URL SHA256 FILE: download and verify, or fail.
fetch() {
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "release-tools.sh: SHA-256 mismatch for $1" >&2; exit 1; }
}
# tarball NAME URL SHA256: install the binary NAME from a release tarball.
tarball() {
  fetch "$2" "$3" "$tmp/$1.tar.gz"
  tar -xzf "$tmp/$1.tar.gz" -C "$tmp" "$1"
  install -m 0755 "$tmp/$1" "$DIR/$1"
}

tarball trivy "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_ASSET}" "$TRIVY_SHA"
tarball grype "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${GRYPE_ASSET}" "$GRYPE_SHA"
tarball syft "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${SYFT_ASSET}" "$SYFT_SHA"
fetch "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/${HADOLINT_ASSET}" "$HADOLINT_SHA" "$tmp/hadolint"
install -m 0755 "$tmp/hadolint" "$DIR/hadolint"
fetch "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/${COSIGN_ASSET}" "$COSIGN_SHA" "$tmp/cosign"
install -m 0755 "$tmp/cosign" "$DIR/cosign"

"$DIR/trivy" --version | head -1
"$DIR/grype" version | grep -m1 '^Version'
"$DIR/syft" version | grep -m1 '^Version'
"$DIR/hadolint" --version
"$DIR/cosign" version 2>&1 | grep -m1 '^GitVersion'
