# Samba Conductor container images

Container images of Samba Conductor, built from the released and signed
packages, with compose files for a lab or evaluation stack.

| Image | Contents | Runs as | Support |
|---|---|---|---|
| `samba-conductor-dc` | Samba AD DC (Debian 13 packages), chronyd, conductor-helper, conductor-backup (for restores), `sc-dc-init` | root in the container, nine capabilities | preview: labs, evaluation and small single-site domains; packages stay the recommended way for production DCs |
| `samba-conductor` | conductor, Samba's `samba-tool` for GPO create and delete | UID 2093, no capabilities | same as the packages |
| `samba-conductor-idp` | conductor-idp (distroless) | UID 2095, no capabilities | same as the packages |
| `samba-conductor-sync` | conductor-sync (distroless) | UID 2094, no capabilities | same as the packages |
| `samba-conductor-backup` | conductor-backup (distroless) | UID 2097, no capabilities | same as the packages |

Every container runs with a read-only root file system, `no-new-privileges`
and no privileged mode. The DC never gets `CAP_SYS_ADMIN` or `CAP_SYS_TIME`:
NT ACLs are kept in the `user.NTACL` extended attribute, and chronyd serves
the host's clock (`-x`) signed through Samba's `ntp_signd`. Passwords and
keys reach the containers only as files, never in environment variables.

## Layout

| Path | What |
|---|---|
| `images/Containerfile` | the five images (targets `dc`, `conductor`, `idp`, `sync`, `backup`) |
| `versions.env` | the component package versions, the Debian snapshot and the base image digests a build uses |
| `scripts/fetch-debs.sh` | downloads the packages and verifies them: the APT repository's signed `InRelease` (the OpenBasalt packages subkey, `keys/`), the `Packages` index, each `.deb` |
| `cmd/sc-dc-init` | the DC image's entry point (PID 1): first boot, refusals, supervision, health |
| `cmd/sc-setup` | the one-shot configuration of the service containers |
| `compose/` | `compose.yaml` (a single DC with conductor) and add-ons (`addons/`) |
| `build-local.sh` | local builds (nothing is pushed) |
| `scripts/ci-smoke.sh` | the smoke test of CI and releases |
| `scripts/release-*.sh` | the release steps: pinned tools, scans and SBOMs, tags, publishing |
| `vex/` | scan exceptions (OpenVEX) |

## The DC entry point

`sc-dc-init` decides from a state file on the data volume what a start does:

| Volume | Start |
|---|---|
| empty | `SC_MODE`: `provision` (a new domain), `join` (an additional DC), `restore` (a full-forest recovery from a conductor-backup archive); `run` is refused with instructions |
| domain complete | runs it; `SC_MODE` is ignored; a different `SC_REALM` or `SC_HOSTNAME` is refused |
| first boot unfinished | refused; `SC_RETRY_FIRST_BOOT=1` wipes what that first boot created and starts again |
| Samba data without a state file | refused (an existing data directory is never adopted) |

At every start it also writes the image's options into `smb.conf`, renews
the self-signed certificates when due, and compares the image's Samba with
the version that last ran the domain: a patch update starts and runs a
read-only `samba-tool dbcheck --cross-ncs`; a minor update needs
`SC_ALLOW_SAMBA_UPGRADE=<new minor>` and takes an offline copy of
`private/` and `sysvol/` first; a downgrade is refused. Unknown `SC_*`
variables and variables that look like secrets (`*PASSWORD*`, `*SECRET*`,
`*_KEY`) are refused.

Other commands: `sc-dc-init health` (the healthcheck), `sc-dc-init account
idp|sync|backup` (service accounts; `backup` gets the three replication
rights and nothing else), `sc-dc-init dns-name NAME...`,
`sc-dc-init show-initial-password` and `forget-initial-password`.

## Quick start (lab)

```sh
cd compose
cp .env.example .env          # domain, NetBIOS name, host name, this host's address
./make-secrets.sh             # random passwords in ./secrets (0600)
docker compose up -d dc       # provisions the domain (about a minute)
docker compose run --rm conductor-setup
docker compose up -d
```

`conductor-setup` prints a one-time enrollment link for the first
administrator. Add-ons are listed in `COMPOSE_FILE` in `.env`
(`addons/idp.yaml`, `sync.yaml`, `backup.yaml`, `host-network.yaml`,
`provided-tls.yaml`, `join.yaml`, `restore.yaml`); each file starts with the
steps it needs.

## Building

```sh
./build-local.sh                         # the packages pinned in versions.env, from the APT repository
./build-local.sh --source local --debs DIR   # packages you built (make package), with their SHA256SUMS
./build-local.sh --platform linux/arm64 --output none
```

`make check` runs the Go gates of `sc-dc-init` and `sc-setup`.

## Releases

Images are released by the release workflow on a version tag, built from
the component packages pinned in `versions.env`, scanned, signed with
cosign (keyless) and published with SBOMs and provenance attestations;
first under the immutable tag and `testing` only. How it works, the
settings it needs and how to verify an image: [RELEASING.md](RELEASING.md).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The images
also contain Debian packages under their own licenses
([images/IMAGE-LICENSES](images/IMAGE-LICENSES)).
