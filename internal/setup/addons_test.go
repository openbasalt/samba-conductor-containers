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

// fakeIDP stands in for /usr/bin/conductor-idp: gen-key writes a key file.
const fakeIDP = `#!/bin/sh
[ "$1" = gen-key ] && echo master >"$2"
`

// addonFixture prepares a root where conductor setup has run (its
// conductor.toml), with what the DC provides, the add-ons' secrets and a
// fake conductor-idp.
func addonFixture(t *testing.T) (*Setup, string, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	// handOver leaves the credentials directories 0500; make them removable.
	t.Cleanup(func() {
		for _, d := range []string{"run/credentials/conductor-idp", "run/credentials/conductor-sync"} {
			_ = os.Chmod(filepath.Join(root, d), 0o700)
		}
	})
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
	write("etc/conductor/conductor.toml", "[server]\nlisten = \":8443\"\n", 0o640)
	write(IssuedDir+"/idp/cert.pem", "cert", 0o644)
	write(IssuedDir+"/idp/key.pem", "key", 0o600)
	write(PublicDir+"/ca.pem", "ca", 0o644)
	write(SecretsDir+"/idp-ad-password", "pw", 0o600)
	write(SecretsDir+"/sync-ad-password", "pw", 0o600)
	write("bin/conductor-idp", fakeIDP, 0o755)
	out := &bytes.Buffer{}
	s := &Setup{
		Env: envcfg.FromList([]string{"SC_REALM=example.test", "SC_DC_HOST=dc1.example.test",
			"SC_PUBLIC_URL=https://conductor.example.test:8443", "SC_IDP_URL=https://idp.example.test:9443",
			"SC_SYNC_EMAIL_DOMAIN=example.com", "SC_SYNC_GOOGLE_ADMIN=admin@example.com"}),
		Out: out, Root: root, BinDir: filepath.Join(root, "bin"),
	}
	return s, root, out
}

// TestAddonSetupNextStep: idp-setup and sync-setup enable their section in
// conductor.toml and name the compose commands that make conductor load
// it (conductor reads its configuration only at start).
func TestAddonSetupNextStep(t *testing.T) {
	for _, tc := range []struct {
		name    string
		run     func(*Setup, context.Context) error
		section string
		label   string
	}{
		{"idp", (*Setup).IDP, "[idp]", "Single sign-on"},
		{"sync", (*Setup).Sync, "[sync]", "Google Workspace sync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root, out := addonFixture(t)
			if err := tc.run(s, context.Background()); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(root, "etc/conductor/conductor.toml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tc.section+"\nenabled = true\n") {
				t.Errorf("%s not enabled in conductor.toml:\n%s", tc.section, b)
			}
			got := out.String()
			for _, w := range []string{"next: docker compose up -d, then docker compose restart conductor", "its " + tc.label + " section"} {
				if !strings.Contains(got, w) {
					t.Errorf("output lacks %q:\n%s", w, got)
				}
			}
			if strings.Contains(got, "systemctl") {
				t.Errorf("a package instruction in the output:\n%s", got)
			}
		})
	}
}

func TestAddonSetupWithoutConductor(t *testing.T) {
	s, root, _ := addonFixture(t)
	if err := os.Remove(filepath.Join(root, "etc/conductor/conductor.toml")); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "run the conductor-setup one-shot first") {
		t.Fatalf("error %v", err)
	}
}

func TestLineRewriter(t *testing.T) {
	var b bytes.Buffer
	w := newLineRewriter(&b, containerNextStep)
	// Lines split across writes, the next step in the middle, and a last
	// line without a newline.
	for _, chunk := range []string{"configuration wr", "itten\nnext: systemctl enable --now con", "ductor-helper conductor\nnext: kept", " as is\ntail"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	want := "configuration written\nnext: docker compose up -d\nnext: kept as is\ntail"
	if b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
	if err := w.Flush(); err != nil || b.String() != want {
		t.Fatalf("second Flush changed the output: %q, %v", b.String(), err)
	}
}
