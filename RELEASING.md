# Releasing the container images

The release workflow (`.github/workflows/release.yml`) builds, tests, scans,
signs and publishes the five images. It runs in two modes.

| Mode | Trigger | What it does |
|---|---|---|
| Dry run | "Run workflow" (workflow_dispatch) on any branch or tag | builds the images on amd64 and arm64, runs the smoke test, the scan gate and the SBOMs, uploads the reports; pushes, signs and releases nothing |
| Release | a pushed tag `vX.Y.Z` or `vX.Y.Z-rc.N` | the dry run steps, then staging in GHCR, signatures and attestations, a copy to Docker Hub after approval, signed release assets |

## Inputs

`versions.env` pins every input of a build, and a release only uses what a
reviewed pull request put there:

- `IMAGE_VERSION`: must equal the tag without the `v` (tag `v0.2.0` needs
  `IMAGE_VERSION=0.2.0`), or the release refuses to run.
- `CONDUCTOR_VERSION`, `IDP_VERSION`, `SYNC_VERSION`, `BACKUP_VERSION`: the
  component packages exactly as published in the OpenBasalt APT repository
  (`X.Y.Z-N` or `X.Y.Z~rc.N-N`). Snapshot versions (`+git<time>.<commit>`) are refused
  on a tag; a dry run lists them as warnings. The images need component
  releases that include the `healthcheck` subcommands and
  `conductor-backup run --loop`.
- `IMAGE_REVISION`: the `-rN` of the image tags. Raise it to rebuild the
  same component versions (Debian security updates, a new base image).
- `DEBIAN_SNAPSHOT`, `DEBIAN_IMAGE`, `DISTROLESS_IMAGE`, `GO_IMAGE`: the
  Debian packages and base images, by snapshot timestamp and digest.

## What a release run does

1. Plan: checks the tag and the inputs above.
2. Per architecture (`ubuntu-24.04` and `ubuntu-24.04-arm`): hadolint, the
   build from the verified packages, `scripts/ci-smoke.sh` (a fresh
   domain, idempotency on recreate, capabilities, read-only root, users),
   then `scripts/release-scan.sh`:
   - CycloneDX 1.6 SBOMs (syft);
   - trivy and grype on every image; the gate fails on any Critical or
     High vulnerability with a fix available and on any secret found;
     unfixed findings are reported only;
   - trivy reports in GitHub code scanning.
3. Staging (tag runs): each per-arch image is pushed to
   `ghcr.io/openbasalt/<image>`, the multi-arch index is created under the
   immutable tag, signed with cosign (keyless, the workflow's identity) and
   the SBOMs are attached as cosign attestations; GitHub build provenance
   and SBOM attestations are created for the same digests.
4. Promotion (tag runs, `container-publish` environment, one approval):
   the index is copied to `docker.io/openbasalt/<image>` under the
   immutable tag and `testing`, the digest is checked to be unchanged,
   signed and attested there and the signature verified.
5. Assets (`release` environment): `IMAGES.txt` (every published reference
   with its digest), the SBOMs and scan reports, `SHA256SUMS` signed with
   the OpenBasalt packages subkey, a Sigstore bundle of `SHA256SUMS`. A
   draft GitHub release only when the repository variable
   `PUBLISH_RELEASE` is `true`.

Each immutable tag is checked before the push: a tag that exists is never
overwritten (raise `IMAGE_REVISION` instead).

## Tags

| Image | Immutable tag | Moving tag |
|---|---|---|
| `samba-conductor-dc` | `<conductor>-samba<samba>-r<N>` (for example `0.2.0-samba4.22.11-r1`) | `testing` |
| `samba-conductor` | `<conductor>-r<N>` | `testing` |
| `samba-conductor-idp`, `-sync`, `-backup` | `<component>-r<N>` | `testing` |

`<component>` is the package version without the Debian revision, with
`~rc.N` written `-rc.N`. The workflow sets no other moving tag: version
tags (`1.2.3`, `1.2`, `1`) and `latest` follow only after a release has
been tested from the registry, as a separate step.

## Settings the workflow needs

- Organization or repository secret `DOCKERHUB_TOKEN` and variable
  `DOCKERHUB_USERNAME` (Docker Hub access token with write access to the
  five repositories).
- Environment `container-publish`: deployment from `v*` tags only, a
  required reviewer.
- Environment `release`: deployment from `v*` tags only, a required
  reviewer, secrets `RELEASE_SIGNING_KEY` and `RELEASE_SIGNING_PASSPHRASE`
  and variable `RELEASE_SIGNING_FPR` (the packages subkey). Without the key
  `SHA256SUMS` is published unsigned, with a warning.
- After the first staging push, the five GHCR packages set to public and
  linked to this repository.

## Verifying an image

```sh
cosign verify docker.io/openbasalt/samba-conductor-dc@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/openbasalt/samba-conductor-containers/\.github/workflows/release\.yml@refs/tags/v'
gh attestation verify oci://docker.io/openbasalt/samba-conductor-dc@sha256:<digest> --owner openbasalt
```

Or verify `SHA256SUMS.asc` with the OpenBasalt release key
(`keys/openbasalt-release-key.asc`), check `IMAGES.txt` against
`SHA256SUMS` and pull by the listed digest.

## Scan exceptions

A finding that does not affect an image (for example, vulnerable code
that is never run) is excepted only through an OpenVEX document in `vex/`,
added by pull request with a justification. See `vex/README.md`.

## Running the steps locally

```sh
scripts/release-tools.sh .tools/release && export PATH="$PWD/.tools/release:$PATH"
./build-local.sh --tag rel
scripts/ci-smoke.sh rel
scripts/release-scan.sh rel amd64 out
scripts/release-meta.sh tags rel
```
