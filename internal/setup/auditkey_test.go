package setup

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAuditKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"

// readKeys returns the audit key on conductor-etc and its handed-over copy
// (empty when missing) and checks their modes.
func readKeys(t *testing.T, root string) (etcKey, credKey string) {
	t.Helper()
	read := func(rel string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		st, err := os.Stat(p)
		if os.IsNotExist(err) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, want %v", rel, st.Mode().Perm(), mode)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read(auditKeyEtc, 0o600), read(auditKeyCred, 0o400)
}

// assertNewKey checks a generated key: 32 random bytes as 64 hex digits and
// a newline, exactly the packages' od | tr; echo.
func assertNewKey(t *testing.T, k string) {
	t.Helper()
	if len(k) != 65 || k[64] != '\n' {
		t.Fatalf("key %d bytes, want 64 hex digits and a newline", len(k))
	}
	if _, err := hex.DecodeString(k[:64]); err != nil {
		t.Fatalf("key is not hex: %v", err)
	}
	if strings.ToLower(k) != k {
		t.Error("key is not lower-case hex")
	}
}

// upgradedVolume lays out conductor-etc and conductor-cred as an earlier
// image left them: configuration, TOTP key and its copy, no audit key.
func upgradedVolume(t *testing.T) (*Setup, string, *bytes.Buffer) {
	t.Helper()
	s, root, out := conductorFixture(t, "ok", false)
	for path, data := range map[string]string{
		"/etc/conductor/conductor.toml":       "[server]\n",
		"/etc/conductor/credentials/totp-key": "totp\n",
		"/run/credentials/conductor/totp-key": "totp\n",
	} {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s, root, out
}

func TestConductorSetupCreatesAuditKey(t *testing.T) {
	// conductor setup of 0.2.x writes no audit key: sc-setup creates it.
	s, root, out := conductorFixture(t, "ok", true)
	if err := s.Conductor(context.Background()); err != nil {
		t.Fatal(err)
	}
	etcKey, credKey := readKeys(t, root)
	assertNewKey(t, etcKey)
	if credKey != etcKey {
		t.Error("the handed-over audit key differs from conductor-etc's")
	}
	if strings.Contains(out.String(), strings.TrimSpace(etcKey)) {
		t.Error("the audit key was written to the output")
	}
	for _, w := range []string{"generated conductor's audit key", "credentials/audit-key offline"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	// A second run keeps it.
	if err := s.Conductor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e2, c2 := readKeys(t, root); e2 != etcKey || c2 != etcKey {
		t.Error("the audit key changed on a second run")
	}
}

func TestConductorSetupKeepsConductorsAuditKey(t *testing.T) {
	// conductor setup of 0.3.0 writes the key: it is handed over as is.
	s, root, out := conductorFixture(t, "ok", true)
	t.Setenv("FAKE_AUDIT", strings.TrimSpace(testAuditKey))
	if err := s.Conductor(context.Background()); err != nil {
		t.Fatal(err)
	}
	etcKey, credKey := readKeys(t, root)
	if etcKey != testAuditKey || credKey != testAuditKey {
		t.Errorf("audit key replaced: etc %q, cred %q", etcKey, credKey)
	}
	if strings.Contains(out.String(), "generated conductor's audit key") {
		t.Error("a key was generated although conductor setup wrote one")
	}
}

func TestConductorKeysBeforeSetup(t *testing.T) {
	s, root, out := conductorFixture(t, "ok", false)
	if err := s.ConductorKeys(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"etc/conductor", "run/credentials/conductor"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s created before conductor-setup", p)
		}
	}
	if !strings.Contains(out.String(), "conductor is not set up yet") {
		t.Errorf("output: %s", out)
	}
}

func TestConductorKeysUpgrade(t *testing.T) {
	s, root, out := upgradedVolume(t)
	if err := s.ConductorKeys(); err != nil {
		t.Fatal(err)
	}
	etcKey, credKey := readKeys(t, root)
	assertNewKey(t, etcKey)
	if credKey != etcKey {
		t.Error("the handed-over audit key differs from conductor-etc's")
	}
	if strings.Contains(out.String(), strings.TrimSpace(etcKey)) {
		t.Error("the audit key was written to the output")
	}
	// The rest of the volumes is untouched.
	for path, want := range map[string]string{
		"/etc/conductor/conductor.toml":       "[server]\n",
		"/etc/conductor/credentials/totp-key": "totp\n",
		"/run/credentials/conductor/totp-key": "totp\n",
	} {
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q, %v", path, b, err)
		}
	}
	st, err := os.Stat(filepath.Join(root, "run/credentials/conductor"))
	if err != nil || st.Mode().Perm() != 0o500 {
		t.Errorf("credentials directory: %v, %v", st, err)
	}
	// Every later start keeps the key.
	for range 2 {
		if err := s.ConductorKeys(); err != nil {
			t.Fatal(err)
		}
		if e, c := readKeys(t, root); e != etcKey || c != etcKey {
			t.Fatal("the audit key changed on a later start")
		}
	}
}

func TestConductorKeysKeepsExistingKey(t *testing.T) {
	s, root, out := upgradedVolume(t)
	p := filepath.Join(root, auditKeyEtc)
	if err := os.WriteFile(p, []byte(testAuditKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ConductorKeys(); err != nil {
		t.Fatal(err)
	}
	if e, c := readKeys(t, root); e != testAuditKey || c != testAuditKey {
		t.Errorf("existing key not kept: etc %q, cred %q", e, c)
	}
	if strings.Contains(out.String(), "generated") {
		t.Errorf("output: %s", out)
	}
}

func TestConductorKeysRawKey(t *testing.T) {
	// 32 raw bytes is a key conductor accepts too.
	s, root, _ := upgradedVolume(t)
	raw := bytes.Repeat([]byte{0xa5}, 32)
	if err := os.WriteFile(filepath.Join(root, auditKeyEtc), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ConductorKeys(); err != nil {
		t.Fatal(err)
	}
	if _, c := readKeys(t, root); c != string(raw) {
		t.Error("raw key not handed over as is")
	}
}

func TestConductorKeysTightensMode(t *testing.T) {
	s, root, out := upgradedVolume(t)
	p := filepath.Join(root, auditKeyEtc)
	if err := os.WriteFile(p, []byte(testAuditKey), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.ConductorKeys(); err != nil {
		t.Fatal(err)
	}
	if e, _ := readKeys(t, root); e != testAuditKey {
		t.Error("key changed")
	}
	if !strings.Contains(out.String(), "now 0600") {
		t.Errorf("output: %s", out)
	}
}

func TestConductorKeysFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		want    string
		// etcLeft is what must be at auditKeyEtc afterwards ("" = nothing).
		etcLeft string
	}{
		{"invalid key", func(t *testing.T, root string) {
			writeT(t, filepath.Join(root, auditKeyEtc), "not a key\n", 0o600)
		}, "does not hold 32 raw bytes or 64 hex digits", "not a key\n"},
		{"empty key", func(t *testing.T, root string) {
			writeT(t, filepath.Join(root, auditKeyEtc), "", 0o600)
		}, "does not hold 32 raw bytes or 64 hex digits", "-"},
		{"key is a directory", func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, auditKeyEtc), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "is not a regular file", "-"},
		{"key is a symbolic link", func(t *testing.T, root string) {
			target := filepath.Join(root, "elsewhere")
			writeT(t, target, testAuditKey, 0o600)
			if err := os.Symlink(target, filepath.Join(root, auditKeyEtc)); err != nil {
				t.Fatal(err)
			}
		}, "is not a regular file", "-"},
		{"source lost, copy present", func(t *testing.T, root string) {
			writeT(t, filepath.Join(root, auditKeyCred), testAuditKey, 0o400)
		}, "Put the key back from your offline copy", ""},
		{"no credentials directory", func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, "etc/conductor/credentials")); err != nil {
				t.Fatal(err)
			}
		}, "run conductor-setup again", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root, _ := upgradedVolume(t)
			tc.prepare(t, root)
			err := s.ConductorKeys()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			p := filepath.Join(root, auditKeyEtc)
			switch tc.etcLeft {
			case "":
				if _, err := os.Lstat(p); err == nil {
					t.Error("an audit key was created")
				}
			case "-":
				// Left as prepared; only checked not to be a new key.
				if b, err := os.ReadFile(p); err == nil && validAuditKey(b) && string(b) != testAuditKey {
					t.Error("the key was replaced")
				}
			default:
				if b, err := os.ReadFile(p); err != nil || string(b) != tc.etcLeft {
					t.Errorf("key changed: %q, %v", b, err)
				}
			}
		})
	}
}

func TestConductorKeysUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	s, root, _ := upgradedVolume(t)
	p := filepath.Join(root, auditKeyEtc)
	writeT(t, p, testAuditKey, 0o000)
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	err := s.ConductorKeys()
	if err == nil || !strings.Contains(err.Error(), "it is not replaced") {
		t.Fatalf("error %v", err)
	}
	_ = os.Chmod(p, 0o600)
	if b, _ := os.ReadFile(p); string(b) != testAuditKey {
		t.Error("the key was replaced")
	}
}

func TestConductorSetupFailsClosedOnBadKey(t *testing.T) {
	// conductor-setup run again on a volume with a damaged key stops too.
	s, root, _ := upgradedVolume(t)
	writeT(t, filepath.Join(root, auditKeyEtc), "damaged\n", 0o600)
	err := s.Conductor(context.Background())
	if err == nil || !strings.Contains(err.Error(), "it is not replaced") {
		t.Fatalf("error %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, auditKeyCred)); err == nil {
		t.Error("a key was handed over")
	}
}

func TestValidAuditKey(t *testing.T) {
	for in, want := range map[string]bool{
		testAuditKey:                        true,
		strings.TrimSpace(testAuditKey):     true,
		strings.ToUpper(testAuditKey):       true,
		string(bytes.Repeat([]byte{0}, 32)): true,
		testAuditKey[:62] + "\n":            false,
		strings.Repeat("zz", 32):            false,
		"":                                  false,
	} {
		if got := validAuditKey([]byte(in)); got != want {
			t.Errorf("validAuditKey(%q) = %v", in, got)
		}
	}
}

func writeT(t *testing.T, p, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}
