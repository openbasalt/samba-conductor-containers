package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// UIDProvisioner is conductor-provisioner's fixed UID (and primary GID).
const UIDProvisioner = 2098

// ouRE is a managed OU DN as sc-dc-init account provisioner prints it:
// OU components with plain names, then the domain's DC components.
var ouRE = regexp.MustCompile(`^(?i:OU=[A-Za-z0-9][A-Za-z0-9 ._-]{0,63})(,(?i:OU=[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}))*(,(?i:DC=[A-Za-z0-9-]{1,63}))+$`)

// sidRE matches a domain group SID in conductor.toml's [roles].
var sidRE = regexp.MustCompile(`S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+`)

// roleGroupSIDs reads the SIDs of conductor's role groups (admin_groups,
// helpdesk_groups, auditor_groups in [roles]) from conductor.toml's text:
// conductor-provisioner must treat their members as privileged.
func roleGroupSIDs(conductorTOML string) []string {
	var out []string
	seen := map[string]bool{}
	in := false
	for _, l := range strings.Split(conductorTOML, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			in = t == "[roles]"
			continue
		}
		if !in || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "admin_groups", "helpdesk_groups", "auditor_groups":
			for _, sid := range sidRE.FindAllString(v, -1) {
				if !seen[sid] {
					seen[sid] = true
					out = append(out, sid)
				}
			}
		}
	}
	return out
}

// managedOUs reads SC_PROVISIONER_OUS: DNs separated by ";" (a DN has
// commas), default OU=People,<domain>. Each must be below the domain head.
func (s *Setup) managedOUs(realm string) ([]string, error) {
	base := baseDN(realm)
	raw := s.Env.Get("SC_PROVISIONER_OUS", "OU=People,"+base)
	var ous []string
	for _, dn := range strings.Split(raw, ";") {
		parts := strings.Split(dn, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		dn = strings.Join(parts, ",")
		if dn == "" {
			continue
		}
		if !ouRE.MatchString(dn) || !strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(base)) {
			return nil, fmt.Errorf("SC_PROVISIONER_OUS: %q is not an OU below %s (OU names: letters, digits, space, '.', '_', '-')", dn, base)
		}
		if strings.Contains(strings.ToLower(dn), "ou=domain controllers") {
			return nil, fmt.Errorf("SC_PROVISIONER_OUS: %q: the Domain Controllers OU is never managed", dn)
		}
		ous = append(ous, dn)
	}
	if len(ous) == 0 {
		return nil, errors.New("SC_PROVISIONER_OUS names no OU")
	}
	return ous, nil
}

// Provisioner configures conductor-provisioner: provisioner.toml, the
// delegated account's password and the state key handed over, and
// conductor's [provisioner] section. The account and its delegation are
// created on the DC first (sc-dc-init account provisioner), with the same
// OUs.
func (s *Setup) Provisioner(ctx context.Context) error {
	realm, dcHost, err := s.common()
	if err != nil {
		return err
	}
	ous, err := s.managedOUs(realm)
	if err != nil {
		return err
	}
	account := s.Env.Get("SC_PROVISIONER_ACCOUNT", "svc-conductor-prov")
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`).MatchString(account) {
		return fmt.Errorf("SC_PROVISIONER_ACCOUNT=%q is not an account name", account)
	}
	ca, err := s.domainCA()
	if err != nil {
		return err
	}
	pw, err := s.readSecret("provisioner-ad-password")
	if err != nil {
		return err
	}
	ctoml, err := os.ReadFile(s.p("/etc/conductor/conductor.toml"))
	if err != nil {
		return fmt.Errorf("conductor is not set up yet (run the conductor-setup one-shot first): %w", err)
	}
	extra := roleGroupSIDs(string(ctoml))
	const etc = "/etc/conductor-provisioner"
	if err := s.install(etc, 0o750, 0, UIDProvisioner); err != nil {
		return err
	}
	if err := s.install(etc+"/credentials", 0o700, 0, 0); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/domain-ca.pem", ca, 0o644, 0, 0); err != nil {
		return err
	}
	sk := etc + "/credentials/state-key"
	if _, err := os.Stat(s.p(sk)); errors.Is(err, os.ErrNotExist) {
		k, err := randomHex(32)
		if err != nil {
			return err
		}
		if err := s.writeFile(sk, []byte(k+"\n"), 0o600, 0, 0); err != nil {
			return err
		}
	}
	stateKey, err := os.ReadFile(s.p(sk))
	if err != nil {
		return err
	}
	if err := s.install("/var/lib/conductor-provisioner", 0o700, UIDProvisioner, UIDProvisioner); err != nil {
		return err
	}
	if err := s.handOver("/run/credentials/conductor-provisioner", UIDProvisioner,
		map[string][]byte{"account-password": pw, "state-key": stateKey}); err != nil {
		return err
	}
	dns := ""
	if a := s.Env.Get("SC_DC_ADDRESS", ""); a != "" {
		dns = "dns_servers = " + tlist([]string{a}) + "\n"
	}
	toml := fmt.Sprintf(`# Written by sc-setup provisioner. Reference: conductor-provisioner
# docs/config.md. The account and its delegation: sc-dc-init account
# provisioner (on the DC), with the same OUs as [scope].
[domain]
realm = %s
ca_file = "%s/domain-ca.pem"
preferred = %[3]s
dcs = %[3]s
%[4]s
[account]
username = %[5]s

[scope]
ous = %[6]s

[privileged]
# conductor's role groups ([roles] of conductor.toml when this was written).
extra_group_sids = %[7]s

[state]
database = "/var/lib/conductor-provisioner/provisioner.db"

[api]
socket = "/run/conductor-provisioner/api.sock"
socket_group = "2093"
allowed_users = ["conductor"]
`, tq(realm), etc, tlist([]string{dcHost}), dns, tq(account), tlist(ous), tlist(extra))
	if _, err := os.Stat(s.p(etc + "/provisioner.toml")); errors.Is(err, os.ErrNotExist) {
		if err := s.writeFile(etc+"/provisioner.toml", []byte(toml), 0o640, 0, UIDProvisioner); err != nil {
			return err
		}
	} else {
		s.logf("provisioner.toml exists: kept (delete it from the provisioner-etc volume to write it again)")
	}
	if err := s.enableInConductor(func(t string) string {
		return tomlSection(t, "provisioner", [][2]string{{"enabled", "true"}, {"socket", tq("/run/conductor-provisioner/api.sock")}})
	}); err != nil {
		return err
	}
	if len(extra) > 0 {
		s.logf("conductor's role groups are privileged for conductor-provisioner: %s", strings.Join(extra, ", "))
	}
	s.logf("conductor-provisioner configured (%s on %s); invitations and resets by e-mail also need e-mail "+
		"(addons/mail.yaml); next: %s", account, strings.Join(ous, "; "), nextAddon("provisioner"))
	return nil
}

// Mail writes conductor's [mail] section (the SMTP relay) and hands the
// relay password over as conductor's smtp-password credential. It runs
// again whenever the relay changes; the other sections stay as they are.
func (s *Setup) Mail(_ context.Context) error {
	host := s.Env.Get("SC_MAIL_HOST", "")
	if host == "" || strings.ContainsAny(host, " /\"\\") {
		return fmt.Errorf("SC_MAIL_HOST=%q: the relay's host name or address is required", host)
	}
	from := s.Env.Get("SC_MAIL_FROM", "")
	if from == "" || strings.ContainsAny(from, "\r\n\"\\") {
		return fmt.Errorf("SC_MAIL_FROM=%q: the sender (address or Name <address>) is required", from)
	}
	security := strings.ToLower(s.Env.Get("SC_MAIL_SECURITY", "starttls"))
	defPort := "587"
	switch security {
	case "starttls":
	case "tls":
		defPort = "465"
	case "none":
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("SC_MAIL_SECURITY=none is accepted only for a loopback relay, not %q", host)
		}
	default:
		return fmt.Errorf("SC_MAIL_SECURITY=%q: starttls, tls or none", security)
	}
	port, err := strconv.Atoi(s.Env.Get("SC_MAIL_PORT", defPort))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("SC_MAIL_PORT=%q is not a port", s.Env.Get("SC_MAIL_PORT", ""))
	}
	maxPerHour, err := strconv.Atoi(s.Env.Get("SC_MAIL_MAX_PER_HOUR", "200"))
	if err != nil || maxPerHour < 1 || maxPerHour > 100000 {
		return fmt.Errorf("SC_MAIL_MAX_PER_HOUR=%q: 1 to 100000", s.Env.Get("SC_MAIL_MAX_PER_HOUR", ""))
	}
	for _, k := range []string{"SC_MAIL_USERNAME", "SC_MAIL_REPLY_TO", "SC_MAIL_HELLO_NAME"} {
		if strings.ContainsAny(s.Env.Get(k, ""), "\r\n\"\\") {
			return fmt.Errorf("%s holds a character that is not allowed", k)
		}
	}
	username := s.Env.Get("SC_MAIL_USERNAME", "")
	set := [][2]string{{"host", tq(host)}, {"port", strconv.Itoa(port)}, {"security", tq(security)},
		{"username", tq(username)}, {"password_file", tq("")}, {"from", tq(from)},
		{"reply_to", tq(s.Env.Get("SC_MAIL_REPLY_TO", ""))}, {"hello_name", tq(s.Env.Get("SC_MAIL_HELLO_NAME", ""))},
		{"max_per_hour", strconv.Itoa(maxPerHour)}}
	if _, err := os.Stat(s.p("/etc/conductor/conductor.toml")); err != nil {
		return fmt.Errorf("conductor is not set up yet (run the conductor-setup one-shot first): %w", err)
	}
	// The relay's CA: the mail-ca secret when it is not empty, copied
	// next to conductor.toml (conductor does not mount the secrets).
	caFile := ""
	if b, err := os.ReadFile(s.p(filepath.Join(SecretsDir, "mail-ca"))); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		caFile = "/etc/conductor/mail-ca.pem"
		if err := s.writeFile(caFile, b, 0o644, 0, 0); err != nil {
			return err
		}
	}
	set = append(set, [2]string{"ca_file", tq(caFile)})
	if username != "" {
		pw, err := s.readSecret("smtp-password")
		if err != nil {
			return fmt.Errorf("%w (SC_MAIL_USERNAME is set: the relay password goes into ./secrets/smtp-password)", err)
		}
		if err := s.handOver("/run/credentials/conductor", UIDConductor, map[string][]byte{"smtp-password": pw}); err != nil {
			return err
		}
	}
	if err := s.enableInConductor(func(t string) string { return tomlSection(t, "mail", set) }); err != nil {
		return err
	}
	auth := "no authentication"
	if username != "" {
		auth = "user " + username
	}
	s.logf("e-mail configured: %s:%d (%s, %s), from %s; next: docker compose restart conductor (conductor reads "+
		"conductor.toml when it starts), then Settings > E-mail > Send a test message", host, port, security, auth, from)
	return nil
}
