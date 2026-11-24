package setup

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// conductor keys its audit chain with an HMAC key (conductor 0.3.0 and
// later refuse to start without it). The packages create it as
// /etc/conductor/credentials/audit-key (root, 0600, 32 random bytes as 64
// hex digits and a newline) and give it to the service with
// LoadCredential=audit-key. Here the same file lives on the conductor-etc
// volume, next to the TOTP key, and the service gets a 0400 copy on the
// conductor-cred volume, as with the TOTP key.
const (
	auditKeyEtc  = "/etc/conductor/credentials/audit-key"
	auditKeyCred = "/run/credentials/conductor/audit-key"
	// auditKeySize is the key length in bytes (conductor's secret.KeySize).
	auditKeySize = 32
)

// ConductorKeys is the conductor-keys one-shot that runs before
// conductor-check at every start: on a deployment set up before conductor
// keyed its audit chain (an upgrade from an earlier image) it creates the
// audit key once, and it hands the key over to conductor. An existing key
// is never replaced. Before conductor-setup has run it does nothing:
// conductor-setup creates the key with the rest of the configuration.
func (s *Setup) ConductorKeys() error {
	if _, err := os.Stat(s.p("/etc/conductor/conductor.toml")); errors.Is(err, os.ErrNotExist) {
		s.logf("conductor is not set up yet: no audit key to hand over (conductor-setup creates it)")
		return nil
	} else if err != nil {
		return err
	}
	key, err := s.ensureAuditKey()
	if err != nil {
		return err
	}
	return s.handOver("/run/credentials/conductor", UIDConductor, map[string][]byte{"audit-key": key})
}

// ensureAuditKey returns conductor's audit key, creating it when it does
// not exist yet, the way the packages do. It fails closed: a key that
// exists but cannot be read or is not a valid key is an error, never
// replaced, because a new key cannot verify the rows chained under the old
// one.
func (s *Setup) ensureAuditKey() ([]byte, error) {
	p := s.p(auditKeyEtc)
	st, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s.createAuditKey()
	case err != nil:
		return nil, fmt.Errorf("the audit key %s: %w (it is not replaced: a new key cannot verify the audit log)", auditKeyEtc, err)
	case !st.Mode().IsRegular():
		return nil, fmt.Errorf("the audit key %s is not a regular file (%v); it is not replaced: a new key cannot verify the audit "+
			"log. Put the key back from your offline copy", auditKeyEtc, st.Mode().Type())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("the audit key %s: %w (it is not replaced: a new key cannot verify the audit log)", auditKeyEtc, err)
	}
	if !validAuditKey(b) {
		return nil, fmt.Errorf("the audit key %s does not hold 32 raw bytes or 64 hex digits; it is not replaced: a new key "+
			"cannot verify the audit log. Put the key back from your offline copy", auditKeyEtc)
	}
	// conductor's command line tools refuse a key readable by group or
	// others, as the packages create it: root only.
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(p, 0o600); err != nil {
			return nil, err
		}
		s.logf("the audit key %s was readable by group or others (mode %v): now 0600", auditKeyEtc, st.Mode().Perm())
	}
	return b, nil
}

// createAuditKey writes a new audit key exactly once (O_EXCL, as the
// packages' "set -C"): 32 random bytes as 64 hex digits and a newline,
// root, 0600. The key is never written to the output.
func (s *Setup) createAuditKey() ([]byte, error) {
	dir := s.p("/etc/conductor/credentials")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, errors.New("the credentials directory /etc/conductor/credentials of the conductor-etc volume is missing " +
			"(conductor setup creates it with the TOTP key): run conductor-setup again")
	}
	// The copy conductor already uses without its source: this volume has
	// lost the key. A new one would not verify the audit log.
	if _, err := os.Lstat(s.p(auditKeyCred)); err == nil {
		return nil, fmt.Errorf("conductor has an audit key on the conductor-cred volume but %s is missing; a new key would not "+
			"verify the audit log, so none is created. Put the key back from your offline copy into %s (root, mode 0600)",
			auditKeyEtc, auditKeyEtc)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := randomHex(auditKeySize)
	if err != nil {
		return nil, err
	}
	b := []byte(k + "\n")
	p := s.p(auditKeyEtc)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating the audit key %s: %w", auditKeyEtc, err)
	}
	werr := writeAndSync(f, b, s.Chown)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return nil, fmt.Errorf("creating the audit key %s: %w", auditKeyEtc, werr)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	s.logf("generated conductor's audit key %s; keep an offline copy with the TOTP key (without it the audit log cannot be verified)", auditKeyEtc)
	return b, nil
}

// writeAndSync writes a new key file, owned by root when chown applies,
// mode 0600 whatever the umask, and flushes it to disk.
func writeAndSync(f *os.File, b []byte, chown bool) error {
	if chown {
		if err := f.Chown(0, 0); err != nil {
			return err
		}
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

// validAuditKey reports whether b is a key conductor accepts: 32 raw bytes
// or 64 hex digits (surrounding white space allowed), as its
// secret.LoadKeyFile.
func validAuditKey(b []byte) bool {
	if len(b) == auditKeySize {
		return true
	}
	s := strings.TrimSpace(string(b))
	if len(s) != 2*auditKeySize {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
