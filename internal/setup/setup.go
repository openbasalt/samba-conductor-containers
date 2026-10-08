// Package setup is sc-setup: the one-shot configuration of the Go service
// containers (conductor, conductor-idp, conductor-sync, conductor-backup).
// It runs as root in the service's own image (the distroless images have
// no shell), writes the configuration volume, and hands each credential to
// the service the way systemd's LoadCredential would: a 0400 copy owned by
// the service UID on a volume the service mounts read-only. Docker Compose
// (without Swarm) ignores the uid, gid and mode of file secrets, which is
// why the copies are needed.
package setup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

// Fixed UIDs (and primary GIDs) of the services: the same number in every
// container, because the sockets between them check the peer's UID.
const (
	UIDConductor = 2093
	UIDSync      = 2094
	UIDIDP       = 2095
	UIDBackup    = 2097
)

// Shared paths.
const (
	SecretsDir = "/run/secrets"
	PublicDir  = "/var/lib/sc-public"
	IssuedDir  = "/var/lib/sc-issued"
)

// Allowed lists the SC_* variables sc-setup knows (every command).
var Allowed = []string{
	"SC_REALM", "SC_DC_HOST", "SC_DC_ADDRESS", "SC_TLS",
	"SC_PUBLIC_URL", "SC_ADMIN_USER", "SC_FIRST_ADMIN", "SC_HELPDESK_GROUP", "SC_AUDITOR_GROUP", "SC_MFA_POLICY",
	"SC_IDP_URL", "SC_IDP_ACCOUNT", "SC_WEBAUTHN_RP_ID",
	"SC_SYNC_ACCOUNT", "SC_SYNC_USER_BASE", "SC_SYNC_EMAIL_DOMAIN", "SC_SYNC_GOOGLE_ADMIN", "SC_SYNC_GOOGLE_API",
	"SC_SYNC_GOOGLE_CA", "SC_SYNC_INTERVAL",
	"SC_HOSTNAME", "SC_BACKUP_S3_ENDPOINT", "SC_BACKUP_S3_REGION", "SC_BACKUP_S3_BUCKET", "SC_BACKUP_S3_PREFIX",
	"SC_BACKUP_S3_CA", "SC_BACKUP_LOCAL_DIR",
}

// Setup carries one run.
type Setup struct {
	Env envcfg.Env
	Out io.Writer
	// Root prefixes every absolute path (tests); "" in the containers.
	Root string
	// Chown is false in tests (not root).
	Chown bool
}

func (s *Setup) p(path string) string { return filepath.Join(s.Root, path) }

func (s *Setup) logf(format string, args ...any) {
	fmt.Fprintf(s.Out, "[sc-setup] "+format+"\n", args...)
}

var realmRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))+$`)

// common reads the realm and the DC's host name.
func (s *Setup) common() (realm, dcHost string, err error) {
	realm = strings.ToUpper(s.Env.Get("SC_REALM", ""))
	if !realmRE.MatchString(realm) {
		return "", "", fmt.Errorf("SC_REALM=%q: the realm is required", realm)
	}
	dcHost = strings.ToLower(s.Env.Get("SC_DC_HOST", ""))
	if dcHost == "" || !strings.HasSuffix(dcHost, "."+strings.ToLower(realm)) {
		return "", "", fmt.Errorf("SC_DC_HOST=%q: the DC's fully qualified name (in %s) is required", dcHost, strings.ToLower(realm))
	}
	return realm, dcHost, nil
}

// baseDN of a realm.
func baseDN(realm string) string {
	return "DC=" + strings.ReplaceAll(strings.ToLower(realm), ".", ",DC=")
}

// install creates a directory with owner and mode (fixing existing ones).
func (s *Setup) install(dir string, mode fs.FileMode, uid, gid int) error {
	d := s.p(dir)
	if err := os.MkdirAll(d, mode); err != nil {
		return err
	}
	if err := os.Chmod(d, mode); err != nil {
		return err
	}
	if s.Chown {
		return os.Chown(d, uid, gid)
	}
	return nil
}

// writeFile writes data with owner and mode.
func (s *Setup) writeFile(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	f := s.p(path)
	tmp := f + ".sc-new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if s.Chown {
		if err := os.Chown(tmp, uid, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp, f)
}

// readSecret reads /run/secrets/<name>.
func (s *Setup) readSecret(name string) ([]byte, error) {
	b, err := os.ReadFile(s.p(filepath.Join(SecretsDir, name)))
	if err != nil {
		return nil, fmt.Errorf("the secret %s: %w", name, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, fmt.Errorf("the secret %s is empty", name)
	}
	return b, nil
}

// handOver copies a credential to the service's credentials volume: 0400,
// owned by its UID (the LoadCredential equivalent), the directory 0500.
func (s *Setup) handOver(credDir string, uid int, names map[string][]byte) error {
	if err := s.install(credDir, 0o700, uid, uid); err != nil {
		return err
	}
	for name, b := range names {
		if err := s.writeFile(filepath.Join(credDir, name), b, 0o400, uid, uid); err != nil {
			return err
		}
	}
	d := s.p(credDir)
	if err := os.Chmod(d, 0o500); err != nil {
		return err
	}
	return nil
}

// tlsPair returns the web certificate and key of a service: issued by the
// DC's self-signed CA (SC_TLS=self-signed), or the provided secrets.
func (s *Setup) tlsPair(service string) (cert, key, ca []byte, err error) {
	mode := strings.ToLower(s.Env.Get("SC_TLS", "self-signed"))
	switch mode {
	case "self-signed":
		dir := s.p(filepath.Join(IssuedDir, service))
		if cert, err = os.ReadFile(filepath.Join(dir, "cert.pem")); err != nil {
			return nil, nil, nil, fmt.Errorf("the DC has not issued the %s certificate yet (start the dc service first): %w", service, err)
		}
		if key, err = os.ReadFile(filepath.Join(dir, "key.pem")); err != nil {
			return nil, nil, nil, err
		}
	case "provided":
		if cert, err = s.readSecret(service + "-tls-cert"); err != nil {
			return nil, nil, nil, err
		}
		if key, err = s.readSecret(service + "-tls-key"); err != nil {
			return nil, nil, nil, err
		}
	default:
		return nil, nil, nil, fmt.Errorf("SC_TLS=%q: self-signed or provided", mode)
	}
	ca, err = s.domainCA()
	return cert, key, ca, err
}

// domainCA is the CA that signs the DC's LDAPS certificate.
func (s *Setup) domainCA() ([]byte, error) {
	if b, err := os.ReadFile(s.p(filepath.Join(PublicDir, "ca.pem"))); err == nil {
		return b, nil
	}
	if b, err := s.readSecret("dc-tls-ca"); err == nil {
		return b, nil
	}
	return nil, errors.New("no domain CA: neither the DC's exported ca.pem (dc-public volume) nor the dc-tls-ca secret")
}

// randomHex returns n random bytes as hex.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// tq quotes a TOML basic string.
func tq(v string) string { return strconv.Quote(v) }

// tlist renders a TOML array of strings.
func tlist(v []string) string {
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = tq(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// runCmd runs a program with optional stdin and its output passed through.
func (s *Setup) runCmd(ctx context.Context, stdin []byte, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout, cmd.Stderr = s.Out, s.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(args[:min(2, len(args))], " "), err)
	}
	return nil
}

// hostOf returns the host name of an https URL.
func hostOf(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Hostname() == "" {
		return "", fmt.Errorf("%q is not an https URL", u)
	}
	return p.Hostname(), nil
}

// tomlSection edits a TOML file at the text level: within [section], each
// key in set is replaced (or added after the header); the section is
// appended when missing. Enough for the flat sections of conductor.toml,
// whose other content stays as conductor setup wrote it.
func tomlSection(text, section string, set [][2]string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	header := "[" + section + "]"
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == header {
			start = i
			break
		}
	}
	if start < 0 {
		out := append(lines, "", header)
		for _, kv := range set {
			out = append(out, kv[0]+" = "+kv[1])
		}
		return strings.Join(out, "\n") + "\n"
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") {
			end = i
			break
		}
	}
	body := append([]string(nil), lines[start+1:end]...)
	for _, kv := range set {
		found := false
		for i, l := range body {
			if k, _, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == kv[0] && !strings.HasPrefix(strings.TrimSpace(l), "#") {
				body[i] = kv[0] + " = " + kv[1]
				found = true
			}
		}
		if !found {
			body = append([]string{kv[0] + " = " + kv[1]}, body...)
		}
	}
	out := append(append(append([]string(nil), lines[:start+1]...), body...), lines[end:]...)
	return strings.Join(out, "\n") + "\n"
}
