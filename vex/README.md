# Scan exceptions (OpenVEX)

`scripts/release-scan.sh` passes every `vex/*.json` file to trivy and
grype. A statement there removes one vulnerability of one product from the
gate. Each exception is a pull request and states why the image is not
affected and until when the statement holds.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/openbasalt/samba-conductor-containers/vex/CVE-YYYY-NNNNN",
  "author": "Samba Conductor maintainers",
  "timestamp": "2026-10-08T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-YYYY-NNNNN"},
      "products": [{"@id": "pkg:deb/debian/<package>@<version>?distro=debian-13"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Why no image runs the affected code. Review by YYYY-MM-DD."
    }
  ]
}
```

Remove the file when the fix reaches the images.
