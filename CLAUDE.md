# samba-conductor-containers: guidelines

Container images of Samba Conductor and their compose files. Read
`../CLAUDE.md` (family rules) first.

- Images are built from the released, signed `.deb` packages (never a
  separate compile); `versions.env` pins every input.
- Go (`sc-dc-init`, `sc-setup`): `GOWORK=off go test ./...`, `go vet`,
  gofmt, staticcheck. Standard library only.
- Security posture: no privileged mode, no `CAP_SYS_ADMIN`/`CAP_SYS_TIME`,
  read-only roots, fixed UIDs 2093 to 2097, secrets only as files.
- Heavy runs (image builds, the container test matrix) on the lab host.
- Public repository: English, no roadmap or internal host names in docs.
- Commit with explicit paths (never `git add -A`).
