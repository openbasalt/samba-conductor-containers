package dc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

func env(kv ...string) envcfg.Env { return envcfg.FromList(kv) }

func TestLoadConfig(t *testing.T) {
	c, confirm, err := Load(env("SC_MODE=provision", "SC_REALM=example.test", "SC_DOMAIN=example", "SC_HOSTNAME=DC1",
		"SC_HOST_IP=192.0.2.10", "SC_DNS_FORWARDERS=192.0.2.1 192.0.2.2", "SC_RESTORE_CONFIRM=example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Realm != "EXAMPLE.TEST" || c.Domain != "EXAMPLE" || c.Hostname != "dc1" || c.FQDN() != "dc1.example.test" ||
		len(c.Forwarders) != 2 || c.NetworkMode != "bridge" || c.TLS != "self-signed" || !c.NTP || confirm != "EXAMPLE.TEST" {
		t.Fatalf("%+v %q", c, confirm)
	}
	for _, bad := range [][]string{
		{"SC_MODE=create"}, {"SC_REALM=single"}, {"SC_HOSTNAME=a_b"}, {"SC_HOST_IP=127.0.0.1"}, {"SC_HOST_IP=::1"},
		{"SC_DNS_FORWARDERS=127.0.0.11"}, {"SC_RPC_PORTS=49159-49152"}, {"SC_RPC_PORTS=80-90"}, {"SC_FUNCTION_LEVEL=2003"},
		{"SC_NETWORK_MODE=nat"}, {"SC_TLS=none"}, {"SC_TYPO=1"}, {"SC_ADMIN_PASSWORD=x"}, {"SC_JOIN_USER=a b"},
	} {
		if _, _, err := Load(env(bad...)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestRequireFirstBoot(t *testing.T) {
	c, _, _ := Load(env("SC_MODE=restore", "SC_REALM=example.test", "SC_HOSTNAME=dc3", "SC_HOST_IP=192.0.2.10"))
	if err := c.requireFirstBoot(""); err == nil || !strings.Contains(err.Error(), "SC_RESTORE_CONFIRM") {
		t.Fatalf("restore without confirmation: %v", err)
	}
	if err := c.requireFirstBoot("OTHER.TEST"); err == nil {
		t.Fatal("restore with the wrong realm confirmed")
	}
	if err := c.requireFirstBoot("EXAMPLE.TEST"); err != nil {
		t.Fatal(err)
	}
	c.Mode = "join"
	if err := c.requireFirstBoot(""); err == nil || !strings.Contains(err.Error(), "SC_JOIN_DC") {
		t.Fatalf("join without SC_JOIN_DC: %v", err)
	}
}

func TestManagedOptions(t *testing.T) {
	c, _, _ := Load(env("SC_REALM=example.test", "SC_HOST_IP=192.0.2.10", "SC_NETWORK_MODE=host"))
	o := c.managedOptions()
	if o["interfaces"] != "192.0.2.10 lo" || o["bind interfaces only"] != "yes" || o["acl_xattr:security_acl_name"] != "user.NTACL" {
		t.Fatalf("host mode: %v", o)
	}
	if _, ok := o["dns update command"]; ok {
		t.Fatal("host mode must not rewrite the DNS update address")
	}
	c.NetworkMode = "bridge"
	o = c.managedOptions()
	if o["dns update command"] != "/usr/sbin/samba_dnsupdate --current-ip=192.0.2.10" || o["interfaces"] != "" {
		t.Fatalf("bridge mode: %v", o)
	}
}

func TestApplyGlobal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "smb.conf")
	orig := "# Global parameters\n[global]\n\tinterfaces = 10.0.0.1 lo\n\tbind interfaces only = Yes\n\tnetbios name = DC1\n\tdns update command = /old --current-ip=1.2.3.4\n\tTLS Enabled = no\n\trealm = EXAMPLE.TEST\n\n[sysvol]\n\tpath = /var/lib/samba/sysvol\n\tread only = No\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	set := map[string]string{"dns update command": "/new", "tls enabled": "yes"}
	if err := applyGlobal(p, set, "/etc/samba/sc-extra.conf"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, want := range []string{"\tdns update command = /new\n", "\ttls enabled = yes\n", "\tnetbios name = DC1\n",
		"\tinclude = /etc/samba/sc-extra.conf\n", "[sysvol]\n\tpath = /var/lib/samba/sysvol\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "/old") || strings.Contains(s, "TLS Enabled = no") || strings.Contains(s, "interfaces") {
		t.Errorf("old values kept:\n%s", s)
	}
	if strings.Index(s, "include =") > strings.Index(s, "[sysvol]") {
		t.Errorf("include is not in [global]:\n%s", s)
	}
	// Idempotent.
	if err := applyGlobal(p, set, "/etc/samba/sc-extra.conf"); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(p)
	if string(b2) != s {
		t.Errorf("second run changed the file:\n%s", b2)
	}
	if v, _ := smbParam(p, "Netbios Name"); v != "DC1" {
		t.Errorf("smbParam = %q", v)
	}
}

func TestValidateExtra(t *testing.T) {
	if err := validateExtra("# comment\nlog level = 2\n; another\nldap server require strong auth = allow_sasl_over_tls\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"[homes]\npath = /x", "tls enabled = no", "Bind Interfaces Only = no", "include = /etc/x",
		"acl_xattr:security_acl_name = security.NTACL", "noequals", "log level = 1 \\"} {
		if err := validateExtra(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUpgradeKind(t *testing.T) {
	v := func(s string) version {
		x, err := parseSambaVersion(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if got := v("Version 4.22.11-Debian-4.22.11+dfsg-0+deb13u1"); got != (version{4, 22, 11}) {
		t.Fatalf("parse: %v", got)
	}
	for _, c := range []struct{ was, now, want string }{
		{"4.22.11", "4.22.11", ""}, {"4.22.10", "4.22.11", "patch"}, {"4.21.9", "4.22.11", "minor"},
		{"4.22.11", "5.0.1", "minor"}, {"4.23.1", "4.22.11", "downgrade"}, {"4.22.12", "4.22.11", "downgrade"},
	} {
		if got := upgradeKind(v(c.was), v(c.now)); got != c.want {
			t.Errorf("%s -> %s = %q, want %q", c.was, c.now, got, c.want)
		}
	}
	if _, err := parseSambaVersion("no version"); err == nil {
		t.Error("garbage parsed")
	}
}

func TestRandomPassword(t *testing.T) {
	for i := 0; i < 50; i++ {
		p, err := randomPassword()
		if err != nil || len(p) != 24 || !strings.ContainsAny(p, "ABCDEFGHJKLMNPQRSTUVWXYZ") ||
			!strings.ContainsAny(p, "abcdefghijkmnopqrstuvwxyz") || !strings.ContainsAny(p, "23456789") || !strings.ContainsAny(p, "-_.+=@%") {
			t.Fatalf("%q %v", p, err)
		}
	}
}

func TestUnicodePwd(t *testing.T) {
	// base64(UTF-16LE("\"ab\""))
	if got := unicodePwd("ab"); got != "IgBhAGIAIgA=" {
		t.Fatalf("%s", got)
	}
}

func TestFirstNameserver(t *testing.T) {
	if got := firstNameserver("# x\nsearch a\nnameserver 127.0.0.1\nnameserver 10.0.0.1\n"); got != "127.0.0.1" {
		t.Fatal(got)
	}
	if got := firstNameserver("options edns0\n"); got != "" {
		t.Fatal(got)
	}
}

func TestDNSRelay(t *testing.T) {
	// An upstream that answers every UDP query with "pong" + the query.
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		b := make([]byte, 512)
		for {
			n, from, err := up.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = up.WriteTo(append([]byte("pong:"), b[:n]...), from)
		}
	}()
	// The relay must listen on a port of its own here (53 needs root).
	upPort := up.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, err := startDNSRelayPort(ctx, "127.0.0.1:0", "127.0.0.1", upPort)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	c, err := net.Dial("udp", relay.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("q1")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "pong:q1" {
		t.Fatalf("%q %v", b[:n], err)
	}
}
