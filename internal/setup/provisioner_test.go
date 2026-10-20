package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

func provisionerFixture(t *testing.T, env ...string) (*Setup, string) {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		for _, d := range []string{"run/credentials/conductor-provisioner", "run/credentials/conductor"} {
			_ = os.Chmod(filepath.Join(root, d), 0o700)
		}
	})
	write := func(path, data string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/conductor/conductor.toml", "[server]\nlisten = \":8443\"\n\n[roles]\n# Group SIDs.\nadmin_groups = []\n"+
		"helpdesk_groups = [\"S-1-5-21-1-2-3-1105\"]\nauditor_groups = [\"S-1-5-21-1-2-3-1106\", \"S-1-5-21-1-2-3-1105\"]\n")
	write(PublicDir+"/ca.pem", "ca")
	write(SecretsDir+"/provisioner-ad-password", "pw")
	s := &Setup{
		Env: envcfg.FromList(append([]string{"SC_REALM=example.test", "SC_DC_HOST=dc1.example.test",
			"SC_DC_ADDRESS=172.30.93.10"}, env...)),
		Out: &bytes.Buffer{}, Root: root,
	}
	return s, root
}

func TestProvisionerSetup(t *testing.T) {
	s, root := provisionerFixture(t)
	if err := s.Provisioner(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "etc/conductor-provisioner/provisioner.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(b)
	for _, want := range []string{
		`realm = "EXAMPLE.TEST"`, `ca_file = "/etc/conductor-provisioner/domain-ca.pem"`,
		`dcs = ["dc1.example.test"]`, `dns_servers = ["172.30.93.10"]`, `username = "svc-conductor-prov"`,
		`ous = ["OU=People,DC=example,DC=test"]`,
		`extra_group_sids = ["S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1106"]`,
		`socket = "/run/conductor-provisioner/api.sock"`, `socket_group = "2093"`, `allowed_users = ["conductor"]`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("provisioner.toml lacks %s:\n%s", want, cfg)
		}
	}
	for _, name := range []string{"account-password", "state-key"} {
		st, err := os.Stat(filepath.Join(root, "run/credentials/conductor-provisioner", name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o400 {
			t.Errorf("%s mode %v", name, st.Mode().Perm())
		}
	}
	key1, _ := os.ReadFile(filepath.Join(root, "etc/conductor-provisioner/credentials/state-key"))
	ct, _ := os.ReadFile(filepath.Join(root, "etc/conductor/conductor.toml"))
	if !strings.Contains(string(ct), "[provisioner]\nenabled = true\nsocket = \"/run/conductor-provisioner/api.sock\"") {
		t.Errorf("conductor.toml:\n%s", ct)
	}
	// A second run keeps the configuration and the state key.
	if err := s.Provisioner(context.Background()); err != nil {
		t.Fatal(err)
	}
	key2, _ := os.ReadFile(filepath.Join(root, "etc/conductor-provisioner/credentials/state-key"))
	if len(key1) != 65 || !bytes.Equal(key1, key2) {
		t.Errorf("state key changed or malformed: %q %q", key1, key2)
	}
	ct2, _ := os.ReadFile(filepath.Join(root, "etc/conductor/conductor.toml"))
	if strings.Count(string(ct2), "[provisioner]") != 1 {
		t.Errorf("[provisioner] twice:\n%s", ct2)
	}
}

func TestProvisionerOUs(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want []string
		bad  bool
	}{
		{"SC_PROVISIONER_OUS=OU=Staff,OU=Lab,DC=example,DC=test; ou=People , dc=example, dc=test",
			[]string{"OU=Staff,OU=Lab,DC=example,DC=test", "ou=People,dc=example,dc=test"}, false},
		{"SC_PROVISIONER_OUS=CN=Users,DC=example,DC=test", nil, true},
		{"SC_PROVISIONER_OUS=DC=example,DC=test", nil, true},
		{"SC_PROVISIONER_OUS=OU=People,DC=other,DC=test", nil, true},
		{"SC_PROVISIONER_OUS=OU=Domain Controllers,DC=example,DC=test", nil, true},
		{"SC_PROVISIONER_OUS=OU=a\\,b,DC=example,DC=test", nil, true},
	} {
		s, _ := provisionerFixture(t, tc.env)
		got, err := s.managedOUs("EXAMPLE.TEST")
		if (err != nil) != tc.bad {
			t.Errorf("%s: err %v", tc.env, err)
			continue
		}
		if !tc.bad && !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.env, got, tc.want)
		}
	}
}

func TestRoleGroupSIDs(t *testing.T) {
	got := roleGroupSIDs("[roles]\nadmin_groups = [\"S-1-5-21-9-9-9-512\"]\n# helpdesk_groups = [\"S-1-5-21-9-9-9-1\"]\n" +
		"cache_seconds = 60\n[sync]\nhelpdesk_groups = [\"S-1-5-21-9-9-9-2\"]\n")
	if !reflect.DeepEqual(got, []string{"S-1-5-21-9-9-9-512"}) {
		t.Errorf("got %q", got)
	}
}

func TestMailSetup(t *testing.T) {
	s, root := provisionerFixture(t, "SC_MAIL_HOST=smtp.example.test", "SC_MAIL_FROM=Conductor <no-reply@example.test>",
		"SC_MAIL_USERNAME=relay")
	if err := s.Mail(context.Background()); err == nil || !strings.Contains(err.Error(), "smtp-password") {
		t.Fatalf("missing relay password: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, SecretsDir, "smtp-password"), []byte("relay-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, SecretsDir, "mail-ca"), []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Mail(context.Background()); err != nil {
		t.Fatal(err)
	}
	ct, _ := os.ReadFile(filepath.Join(root, "etc/conductor/conductor.toml"))
	for _, want := range []string{"[mail]\n", `host = "smtp.example.test"`, "port = 587", `security = "starttls"`,
		`username = "relay"`, `from = "Conductor <no-reply@example.test>"`, `ca_file = "/etc/conductor/mail-ca.pem"`} {
		if !strings.Contains(string(ct), want) {
			t.Errorf("conductor.toml lacks %s:\n%s", want, ct)
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "run/credentials/conductor/smtp-password")); err != nil || string(b) != "relay-pw\n" {
		t.Errorf("smtp-password: %q %v", b, err)
	}
	// A plain relay is refused unless it is on loopback.
	for _, env := range [][]string{{"SC_MAIL_SECURITY=none"}, {"SC_MAIL_SECURITY=starttls", "SC_MAIL_PORT=99999"},
		{"SC_MAIL_FROM="}, {"SC_MAIL_SECURITY=ssl"}} {
		s2, _ := provisionerFixture(t, append([]string{"SC_MAIL_HOST=smtp.example.test", "SC_MAIL_FROM=a@example.test"}, env...)...)
		if err := s2.Mail(context.Background()); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
	s3, _ := provisionerFixture(t, "SC_MAIL_HOST=127.0.0.1", "SC_MAIL_SECURITY=none", "SC_MAIL_FROM=a@example.test")
	if err := s3.Mail(context.Background()); err != nil {
		t.Errorf("loopback relay without TLS: %v", err)
	}
}
