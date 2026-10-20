package setup

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

// fakeConductor stands in for /usr/bin/conductor: FAKE_MODE=fail exits 1,
// noconfig exits 0 without writing anything, ok writes the TOTP key and
// conductor.toml into FAKE_ETC the way conductor setup does (key first)
// and ends with the packages' next step, as conductor setup does.
const fakeConductor = `#!/bin/sh
case "$FAKE_MODE" in
fail) echo "conductor: setup: ldap: connection refused" >&2; exit 1 ;;
noconfig) exit 0 ;;
ok)
  mkdir -p "$FAKE_ETC/credentials"
  echo key >"$FAKE_ETC/credentials/totp-key"
  echo '[server]' >"$FAKE_ETC/conductor.toml"
  echo "configuration written to $FAKE_ETC/conductor.toml"
  echo "enrollment link on stderr" >&2
  printf 'next: systemctl enable --now conductor-helper conductor\n'
  ;;
esac
`

// conductorFixture prepares a root with what the DC provides (the issued
// web certificate, the exported CA) and a fake conductor program.
func conductorFixture(t *testing.T, mode string, withPassword bool) (*Setup, string, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	// handOver leaves the credentials directory 0500; make it removable.
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "run/credentials/conductor"), 0o700) })
	write := func(path, data string, mode fs.FileMode) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(IssuedDir+"/conductor/cert.pem", "cert", 0o644)
	write(IssuedDir+"/conductor/key.pem", "key", 0o600)
	write(PublicDir+"/ca.pem", "ca", 0o644)
	if withPassword {
		write(SecretsDir+"/admin-password", "pw", 0o600)
	}
	write("bin/conductor", fakeConductor, 0o755)
	t.Setenv("FAKE_MODE", mode)
	t.Setenv("FAKE_ETC", filepath.Join(root, "etc/conductor"))
	out := &bytes.Buffer{}
	s := &Setup{
		Env: envcfg.FromList([]string{"SC_REALM=example.test", "SC_DC_HOST=dc1.example.test",
			"SC_PUBLIC_URL=https://conductor.example.test:8443"}),
		Out: out, Root: root, BinDir: filepath.Join(root, "bin"),
	}
	return s, root, out
}

func TestConductorSetupOK(t *testing.T) {
	s, root, out := conductorFixture(t, "ok", true)
	if err := s.Conductor(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The packages' next step is replaced by the stack's; the rest of
	// conductor setup's output passes through in order.
	got := out.String()
	if strings.Contains(got, "systemctl") {
		t.Errorf("the packages' next step was relayed:\n%s", got)
	}
	want := "configuration written to " + filepath.Join(root, "etc/conductor/conductor.toml") +
		"\nenrollment link on stderr\nnext: docker compose up -d\n"
	if !strings.Contains(got, want) {
		t.Errorf("output lacks %q:\n%s", want, got)
	}
	for _, p := range []string{"etc/conductor/conductor.toml", "run/credentials/conductor/totp-key"} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc/conductor/domain-ca-input.pem")); err == nil {
		t.Error("domain-ca-input.pem left behind")
	}
	// A second run keeps the configuration.
	if err := s.Conductor(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
}

func TestConductorSetupErrors(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		password   bool
		want       []string
	}{
		{"no admin password", "ok", false, []string{"admin-password", "./secrets/admin-password", "make-secrets.sh"}},
		{"conductor setup fails", "fail", true, []string{"conductor setup failed", "was not written", "docker compose ps dc", "run conductor-setup again"}},
		{"no configuration written", "noconfig", true, []string{"ended without writing /etc/conductor/conductor.toml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root, _ := conductorFixture(t, tc.mode, tc.password)
			err := s.Conductor(context.Background())
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "etc/conductor/conductor.toml")); err == nil {
				t.Error("conductor.toml written")
			}
		})
	}
}

func TestConductorSetupConfigWithoutKey(t *testing.T) {
	s, root, out := conductorFixture(t, "ok", true)
	p := filepath.Join(root, "etc/conductor/conductor.toml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[server]\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := s.Conductor(context.Background())
	if err == nil || !strings.Contains(err.Error(), "delete conductor.toml from the conductor-etc volume") {
		t.Fatalf("error %v", err)
	}
	if !strings.Contains(out.String(), "conductor.toml exists: kept") {
		t.Errorf("output: %s", out)
	}
}

func TestConductorSetupDCNotReady(t *testing.T) {
	s, root, _ := conductorFixture(t, "ok", true)
	if err := os.RemoveAll(filepath.Join(root, IssuedDir)); err != nil {
		t.Fatal(err)
	}
	err := s.Conductor(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start the dc service first") {
		t.Fatalf("error %v", err)
	}
}
