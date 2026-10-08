package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var groupRE = regexp.MustCompile(`^[^"\\\x00-\x1f]{1,64}$`)

// Conductor configures conductor: web certificate, `conductor setup`
// (non-interactive, the Administrator password on stdin), and the TOTP key
// handed over to the conductor container.
func (s *Setup) Conductor(ctx context.Context) error {
	realm, dcHost, err := s.common()
	if err != nil {
		return err
	}
	publicURL := s.Env.Get("SC_PUBLIC_URL", "")
	if _, err := hostOf(publicURL); err != nil {
		return fmt.Errorf("SC_PUBLIC_URL: %w (the URL users open, e.g. https://conductor.%s:8443)", err, strings.ToLower(realm))
	}
	cert, key, ca, err := s.tlsPair("conductor")
	if err != nil {
		return err
	}
	const etc = "/etc/conductor"
	if err := s.install(etc, 0o750, 0, UIDConductor); err != nil {
		return err
	}
	if err := s.install(etc+"/tls", 0o750, 0, UIDConductor); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/tls/cert.pem", cert, 0o644, 0, 0); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/tls/key.pem", key, 0o640, 0, UIDConductor); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/domain-ca-input.pem", ca, 0o644, 0, 0); err != nil {
		return err
	}
	if err := s.install("/var/lib/conductor", 0o700, UIDConductor, UIDConductor); err != nil {
		return err
	}
	if _, err := os.Stat(s.p(etc + "/conductor.toml")); errors.Is(err, os.ErrNotExist) {
		pw, err := s.readSecret("admin-password")
		if err != nil {
			return fmt.Errorf("conductor setup resolves the role groups with the Administrator account: %w", err)
		}
		args := []string{"setup", "--non-interactive", "--realm", realm, "--dc", dcHost, "--ca-file", s.p(etc + "/domain-ca-input.pem"),
			"--admin-user", s.Env.Get("SC_ADMIN_USER", "Administrator"), "--first-admin", s.Env.Get("SC_FIRST_ADMIN", "Administrator"),
			"--public-url", publicURL, "--mfa-policy", s.Env.Get("SC_MFA_POLICY", "optional")}
		for _, g := range [][2]string{{"--helpdesk-group", "SC_HELPDESK_GROUP"}, {"--auditor-group", "SC_AUDITOR_GROUP"}} {
			if v := s.Env.Get(g[1], ""); v != "" {
				if !groupRE.MatchString(v) {
					return fmt.Errorf("%s=%q is not a group name", g[1], v)
				}
				args = append(args, g[0], v)
			}
		}
		if err := s.runCmd(ctx, append(pw, '\n'), "/usr/bin/conductor", args...); err != nil {
			return err
		}
	} else {
		s.logf("conductor.toml exists: kept (delete it from the conductor-etc volume to run conductor setup again)")
	}
	_ = os.Remove(s.p(etc + "/domain-ca-input.pem"))
	totp, err := os.ReadFile(s.p(etc + "/credentials/totp-key"))
	if err != nil {
		return fmt.Errorf("the TOTP key conductor setup writes: %w", err)
	}
	if err := s.handOver("/run/credentials/conductor", UIDConductor, map[string][]byte{"totp-key": totp}); err != nil {
		return err
	}
	s.logf("conductor configured; keep a copy of %s/credentials/totp-key offline (restore.md section 0)", etc)
	return nil
}

// enableInConductor edits conductor.toml (on the conductor-etc volume) for
// the services that plug into conductor.
func (s *Setup) enableInConductor(edit func(string) string) error {
	p := "/etc/conductor/conductor.toml"
	b, err := os.ReadFile(s.p(p))
	if err != nil {
		return fmt.Errorf("conductor is not set up yet (run the conductor-setup one-shot first): %w", err)
	}
	return s.writeFile(p, []byte(edit(string(b))), 0o640, 0, UIDConductor)
}

// IDP configures conductor-idp: idp.toml, the master key and the service
// account password handed over, conductor's [idp] section (panel section
// and the 2FA socket) and shared WebAuthn keys.
func (s *Setup) IDP(ctx context.Context) error {
	realm, dcHost, err := s.common()
	if err != nil {
		return err
	}
	issuer := s.Env.Get("SC_IDP_URL", "")
	idpHost, err := hostOf(issuer)
	if err != nil {
		return fmt.Errorf("SC_IDP_URL: %w", err)
	}
	cert, key, ca, err := s.tlsPair("idp")
	if err != nil {
		return err
	}
	adPW, err := s.readSecret("idp-ad-password")
	if err != nil {
		return err
	}
	const etc = "/etc/conductor-idp"
	for _, d := range []string{etc, etc + "/tls"} {
		if err := s.install(d, 0o750, 0, UIDIDP); err != nil {
			return err
		}
	}
	if err := s.install(etc+"/credentials", 0o700, 0, 0); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/tls/cert.pem", cert, 0o644, 0, 0); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/tls/key.pem", key, 0o640, 0, UIDIDP); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/domain-ca.pem", ca, 0o644, 0, 0); err != nil {
		return err
	}
	mk := etc + "/credentials/master-key"
	if _, err := os.Stat(s.p(mk)); errors.Is(err, os.ErrNotExist) {
		if err := s.runCmd(ctx, nil, "/usr/bin/conductor-idp", "gen-key", s.p(mk)); err != nil {
			return err
		}
	}
	master, err := os.ReadFile(s.p(mk))
	if err != nil {
		return err
	}
	if err := s.install("/var/lib/conductor-idp", 0o700, UIDIDP, UIDIDP); err != nil {
		return err
	}
	if err := s.handOver("/run/credentials/conductor-idp", UIDIDP, map[string][]byte{"master-key": master, "ad-password": adPW}); err != nil {
		return err
	}
	dcs := ""
	if a := s.Env.Get("SC_DC_ADDRESS", ""); a != "" {
		dcs = "dns_servers = " + tlist([]string{a}) + "\n"
	}
	toml := fmt.Sprintf(`# Written by sc-setup idp. Reference: conductor-idp docs/config.md.
[server]
issuer = %s
listen = ":9443"
tls_cert = "%[2]s/tls/cert.pem"
tls_key = "%[2]s/tls/key.pem"

[domain]
realm = %[3]s
ca_file = "%[2]s/domain-ca.pem"
preferred = %[4]s
dcs = %[4]s
%[5]s
[service_account]
username = %[6]s

[mfa]
policy = "optional"
backend = "conductor"
conductor_socket = "/run/conductor/mfa.sock"

[saml]
enabled = true

[api]
enabled = true
socket = "/run/conductor-idp/api.sock"
socket_group = "2093"
allowed_users = ["conductor"]
`, tq(issuer), etc, tq(realm), tlist([]string{dcHost}), dcs, tq(s.Env.Get("SC_IDP_ACCOUNT", "svc-conductor-idp")))
	if _, err := os.Stat(s.p(etc + "/idp.toml")); errors.Is(err, os.ErrNotExist) {
		if err := s.writeFile(etc+"/idp.toml", []byte(toml), 0o640, 0, UIDIDP); err != nil {
			return err
		}
	} else {
		s.logf("idp.toml exists: kept")
	}
	conductorURL := s.Env.Get("SC_PUBLIC_URL", "")
	rpID := s.Env.Get("SC_WEBAUTHN_RP_ID", strings.ToLower(realm))
	if !strings.HasSuffix(idpHost, "."+rpID) && idpHost != rpID {
		return fmt.Errorf("SC_WEBAUTHN_RP_ID=%q must be the IdP's host name or a parent domain of it (%s), so passkeys work at both", rpID, idpHost)
	}
	origins := []string{issuer}
	if conductorURL != "" {
		origins = append([]string{strings.TrimRight(conductorURL, "/")}, origins...)
	}
	err = s.enableInConductor(func(t string) string {
		t = tomlSection(t, "idp", [][2]string{{"enabled", "true"}, {"socket", tq("/run/conductor-idp/api.sock")},
			{"mfa_socket", "true"}, {"mfa_socket_path", tq("/run/conductor/mfa.sock")}, {"mfa_socket_group", tq("2095")}})
		return tomlSection(t, "webauthn", [][2]string{{"rp_id", tq(rpID)}, {"origins", tlist(origins)}})
	})
	if err != nil {
		return err
	}
	s.logf("conductor-idp configured (%s); restart conductor to enable its Single sign-on section", issuer)
	return nil
}

// Sync configures conductor-sync (bootstrap configuration in dry-run; the
// sync settings are then edited in conductor) and conductor's [sync]
// section. The state key is generated once and never leaves the volumes.
func (s *Setup) Sync(ctx context.Context) error {
	realm, dcHost, err := s.common()
	if err != nil {
		return err
	}
	emailDomain := strings.ToLower(s.Env.Get("SC_SYNC_EMAIL_DOMAIN", ""))
	admin := s.Env.Get("SC_SYNC_GOOGLE_ADMIN", "")
	if emailDomain == "" || admin == "" {
		return errors.New("SC_SYNC_EMAIL_DOMAIN (the Google Workspace primary domain) and SC_SYNC_GOOGLE_ADMIN (the administrator to act as) are required")
	}
	ca, err := s.domainCA()
	if err != nil {
		return err
	}
	bind, err := s.readSecret("sync-ad-password")
	if err != nil {
		return err
	}
	const etc = "/etc/conductor-sync"
	if err := s.install(etc, 0o750, 0, UIDSync); err != nil {
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
	if err := s.install("/var/lib/conductor-sync", 0o700, UIDSync, UIDSync); err != nil {
		return err
	}
	if err := s.handOver("/run/credentials/conductor-sync", UIDSync, map[string][]byte{"ad-bind": bind, "state-key": stateKey}); err != nil {
		return err
	}
	var google strings.Builder
	fmt.Fprintf(&google, "admin_subject = %s\n", tq(admin))
	if v := s.Env.Get("SC_SYNC_GOOGLE_API", ""); v != "" {
		fmt.Fprintf(&google, "api_base_url = %s\n", tq(v))
	}
	if v := s.Env.Get("SC_SYNC_GOOGLE_CA", ""); v != "" {
		fmt.Fprintf(&google, "ca_file = %s\n", tq(v))
	}
	dns := ""
	if a := s.Env.Get("SC_DC_ADDRESS", ""); a != "" {
		dns = "dns_servers = " + tlist([]string{a}) + "\n"
	}
	toml := fmt.Sprintf(`# Written by sc-setup sync: the bootstrap configuration. The sync settings
# are edited in conductor (Google Workspace sync > Setup).
mode = "dry-run"
state_dir = "/var/lib/conductor-sync"
credentials_dir = "/run/credentials/conductor-sync"

[source]
realm = %s
dcs = %s
%sca_file = "%s/domain-ca.pem"
bind_user = %s
password_credential = "ad-bind"
user_bases = %s

[mapping]
primary_email = ["{sAMAccountName|ascii|lower}@%s"]
allowed_domains = %s

[google]
%s
[schedule]
# No systemd timer in a container: conductor-sync serve runs the schedule.
interval = %s
in_process = true

[api]
socket = "/run/conductor-sync/api.sock"
allowed_users = ["conductor"]
socket_group = "2093"
`, tq(realm), tlist([]string{dcHost}), dns, etc, tq(s.Env.Get("SC_SYNC_ACCOUNT", "svc-conductor-sync")),
		tlist([]string{s.Env.Get("SC_SYNC_USER_BASE", baseDN(realm))}), emailDomain, tlist([]string{emailDomain}),
		google.String(), tq(s.Env.Get("SC_SYNC_INTERVAL", "15m")))
	if _, err := os.Stat(s.p(etc + "/conductor-sync.toml")); errors.Is(err, os.ErrNotExist) {
		if err := s.writeFile(etc+"/conductor-sync.toml", []byte(toml), 0o640, 0, UIDSync); err != nil {
			return err
		}
	} else {
		s.logf("conductor-sync.toml exists: kept")
	}
	if err := s.enableInConductor(func(t string) string {
		return tomlSection(t, "sync", [][2]string{{"enabled", "true"}, {"socket", tq("/run/conductor-sync/api.sock")}})
	}); err != nil {
		return err
	}
	s.logf("conductor-sync configured (dry-run); restart conductor to enable its Google Workspace sync section")
	return nil
}

// RecipientsFile is the operator's recipients list (compose configs:).
const RecipientsFile = "/etc/sc/backup-recipients.txt"

// Backup configures conductor-backup on the DC side: its configuration,
// the signing key (generated here; prints the public key), the S3
// credential handed over, and the state directory with spool/ and
// requests/.
func (s *Setup) Backup(ctx context.Context) error {
	realm, _, err := s.common()
	if err != nil {
		return err
	}
	host := strings.ToLower(s.Env.Get("SC_HOSTNAME", ""))
	if host == "" {
		return errors.New("SC_HOSTNAME (the DC's short host name) is required")
	}
	rec, err := os.ReadFile(s.p(RecipientsFile))
	if err != nil {
		return fmt.Errorf("the recipients file %s (age recipients of the operators' offline keys and the drill host): %w", RecipientsFile, err)
	}
	const etc = "/etc/conductor-backup"
	if err := s.install(etc, 0o750, 0, UIDBackup); err != nil {
		return err
	}
	if err := s.install(etc+"/credentials", 0o700, 0, 0); err != nil {
		return err
	}
	if err := s.writeFile(etc+"/recipients.txt", rec, 0o644, 0, 0); err != nil {
		return err
	}
	keyP := etc + "/credentials/signing-key"
	if _, err := os.Stat(s.p(keyP)); errors.Is(err, os.ErrNotExist) {
		if err := s.runCmd(ctx, nil, "/usr/bin/conductor-backup", "keygen", "signing", "--out", s.p(keyP)); err != nil {
			return err
		}
	}
	signing, err := os.ReadFile(s.p(keyP))
	if err != nil {
		return err
	}
	creds := map[string][]byte{"signing-key": signing}
	var dests strings.Builder
	if ep := s.Env.Get("SC_BACKUP_S3_ENDPOINT", ""); ep != "" {
		bucket := s.Env.Get("SC_BACKUP_S3_BUCKET", "")
		if bucket == "" {
			return errors.New("SC_BACKUP_S3_BUCKET is required with SC_BACKUP_S3_ENDPOINT")
		}
		s3, err := s.readSecret("s3")
		if err != nil {
			return err
		}
		creds["s3"] = s3
		fmt.Fprintf(&dests, "\n[[destination]]\nname = \"s3\"\ntype = \"s3\"\nendpoint = %s\nregion = %s\nbucket = %s\nprefix = %s\npath_style = true\ncredentials = \"s3\"\n",
			tq(ep), tq(s.Env.Get("SC_BACKUP_S3_REGION", "us-east-1")), tq(bucket), tq(s.Env.Get("SC_BACKUP_S3_PREFIX", "")))
		if caf := s.Env.Get("SC_BACKUP_S3_CA", ""); caf != "" {
			// A CA given as a secret is copied next to the configuration
			// (the backup container does not mount the setup's secrets).
			if strings.HasPrefix(caf, SecretsDir+"/") {
				b, err := s.readSecret(filepath.Base(caf))
				if err != nil {
					return err
				}
				caf = etc + "/s3-ca.pem"
				if err := s.writeFile(caf, b, 0o644, 0, 0); err != nil {
					return err
				}
			}
			fmt.Fprintf(&dests, "ca_file = %s\n", tq(caf))
		}
	}
	if dir := s.Env.Get("SC_BACKUP_LOCAL_DIR", ""); dir != "" {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("SC_BACKUP_LOCAL_DIR=%q must be absolute", dir)
		}
		if err := s.install(dir, 0o700, UIDBackup, UIDBackup); err != nil {
			return err
		}
		fmt.Fprintf(&dests, "\n[[destination]]\nname = \"local\"\ntype = \"local\"\npath = %s\n", tq(dir))
	}
	if dests.Len() == 0 {
		return errors.New("no destination: set SC_BACKUP_S3_ENDPOINT (and SC_BACKUP_S3_BUCKET, the s3 secret) or SC_BACKUP_LOCAL_DIR")
	}
	toml := fmt.Sprintf(`# Written by sc-setup backup. Reference: conductor-backup's README.
realm = %s
dc = %s
state_dir = "/var/lib/conductor-backup"
helper_socket = "/run/conductor-helper/backup.sock"
credentials_dir = "/run/credentials/conductor-backup"
signing_key = "signing-key"
recipients_file = "%s/recipients.txt"
verify_after_upload = true
%s`, tq(realm), tq(host), etc, dests.String())
	if _, err := os.Stat(s.p(etc + "/conductor-backup.toml")); errors.Is(err, os.ErrNotExist) {
		if err := s.writeFile(etc+"/conductor-backup.toml", []byte(toml), 0o640, 0, UIDBackup); err != nil {
			return err
		}
	} else {
		s.logf("conductor-backup.toml exists: kept")
	}
	for _, d := range []string{"/var/lib/conductor-backup", "/var/lib/conductor-backup/spool", "/var/lib/conductor-backup/requests"} {
		if err := s.install(d, 0o700, UIDBackup, UIDBackup); err != nil {
			return err
		}
	}
	if err := s.handOver("/run/credentials/conductor-backup", UIDBackup, creds); err != nil {
		return err
	}
	if err := s.runCmd(ctx, nil, "/usr/bin/conductor-backup", "pubkey", s.p(keyP)); err != nil {
		return err
	}
	s.logf("conductor-backup configured; the public signing key above goes into backup_public_keys of a restore configuration")
	return nil
}
