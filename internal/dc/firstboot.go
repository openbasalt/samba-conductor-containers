package dc

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/openbasalt/samba-conductor-containers/internal/state"
)

// provision creates a new domain: samba-tool domain provision with the
// image's options and no --adminpass (Samba sets a random one), then the
// TLS files and the Administrator password through an LDIF on tmpfs.
func (r *Runner) provision(ctx context.Context) error {
	c := r.Cfg
	pw, generated, err := adminPassword()
	if err != nil {
		return err
	}
	_ = os.Remove(DefaultSmbConf)
	args := []string{"domain", "provision", "--use-rfc2307", "--realm=" + c.Realm, "--domain=" + c.Domain,
		"--server-role=dc", "--dns-backend=SAMBA_INTERNAL", "--function-level=" + c.FunctionLevel,
		"--host-name=" + c.Hostname, "--host-ip=" + c.HostIP}
	if c.HostIP6 != "" {
		args = append(args, "--host-ip6="+c.HostIP6)
	}
	args = append(args, c.provisionOptions()...)
	r.logf("provisioning %s (NetBIOS %s, DC %s, level %s, %s networking, advertised %s)", c.Realm, c.Domain, c.FQDN(),
		c.FunctionLevel, c.NetworkMode, c.HostIP)
	if err := r.runCmd(ctx, nil, "/usr/bin/samba-tool", args...); err != nil {
		return err
	}
	if err := r.ensureTLS(DefaultPrivate); err != nil {
		return err
	}
	if err := r.setAdministratorPassword(ctx, pw); err != nil {
		return err
	}
	if generated {
		if err := os.WriteFile(InitialPasswordFile, []byte(pw+"\n"), 0o400); err != nil {
			return err
		}
		r.logf("no admin-password secret: generated the Administrator password into %s (read it with "+
			"`sc-dc-init show-initial-password`, then `sc-dc-init forget-initial-password`)", InitialPasswordFile)
	}
	return nil
}

// adminPassword reads the admin-password secret or generates one.
func adminPassword() (string, bool, error) {
	b, err := os.ReadFile(filepath.Join(SecretsDir, "admin-password"))
	if err == nil {
		pw := strings.TrimRight(string(b), "\r\n")
		if pw == "" {
			return "", false, errors.New("the admin-password secret is empty")
		}
		return pw, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	pw, err := randomPassword()
	return pw, true, err
}

// unicodePwd encodes a password for the unicodePwd attribute.
func unicodePwd(pw string) string {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// setAdministratorPassword writes the password through an LDIF file on the
// container's tmpfs (never a command line or the environment).
func (r *Runner) setAdministratorPassword(ctx context.Context, pw string) error {
	base := "DC=" + strings.ReplaceAll(r.Cfg.DNSDomain(), ".", ",DC=")
	ldif := fmt.Sprintf("dn: CN=Administrator,CN=Users,%s\nchangetype: modify\nreplace: unicodePwd\nunicodePwd:: %s\n", base, unicodePwd(pw))
	f, err := os.CreateTemp(RunDir, "admin-*.ldif")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(ldif); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/ldbmodify", "-H", filepath.Join(DefaultPrivate, "sam.ldb"), f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("setting the Administrator password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	r.logf("Administrator password set")
	return nil
}

// join adds this container as a DC of an existing domain.
func (r *Runner) join(ctx context.Context) error {
	c := r.Cfg
	pwFile := filepath.Join(SecretsDir, "join-password")
	if _, err := os.Stat(pwFile); err != nil {
		return fmt.Errorf("SC_MODE=join needs the join-password secret (the password of %s): %w", c.JoinUser, err)
	}
	krb5, err := r.joinKrb5()
	if err != nil {
		return err
	}
	env := []string{"KRB5_CONFIG=" + krb5, "PASSWD_FILE=" + pwFile}
	if err := r.checkSkew(ctx); err != nil {
		return err
	}
	if err := r.checkStaleDC(ctx, env); err != nil {
		return err
	}
	_ = os.Remove(DefaultSmbConf)
	args := []string{"domain", "join", c.Realm, "DC", "--server=" + c.JoinDC, "-U", c.Realm + `\` + c.JoinUser,
		"--dns-backend=SAMBA_INTERNAL", "--option=netbios name = " + strings.ToUpper(c.Hostname)}
	args = append(args, c.provisionOptions()...)
	r.logf("joining %s as DC %s through %s", c.Realm, c.FQDN(), c.JoinDC)
	if err := r.runCmd(ctx, env, "/usr/bin/samba-tool", args...); err != nil {
		return err
	}
	r.logf("joined. Samba does not replicate SYSVOL: edit GPOs on one DC and copy sysvol to the others (then samba-tool ntacl sysvolreset)")
	return r.ensureTLS(DefaultPrivate)
}

// joinKrb5 writes a krb5.conf that sends Kerberos to SC_JOIN_DC during the
// join (the container's resolver points at itself, where nothing answers
// yet).
func (r *Runner) joinKrb5() (string, error) {
	c := r.Cfg
	p := filepath.Join(RunDir, "join-krb5.conf")
	s := fmt.Sprintf("[libdefaults]\n\tdefault_realm = %s\n\tdns_lookup_kdc = false\n\tdns_lookup_realm = false\n\n[realms]\n\t%s = {\n\t\tkdc = %s\n\t\tadmin_server = %s\n\t}\n",
		c.Realm, c.Realm, c.JoinDC, c.JoinDC)
	return p, os.WriteFile(p, []byte(s), 0o644)
}

var currentTimeRE = regexp.MustCompile(`(?m)^currentTime: (\d{14})\.0Z`)

// checkSkew compares this host's clock with the target DC's (rootDSE
// currentTime, anonymous): Kerberos refuses more than 5 minutes.
func (r *Runner) checkSkew(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/ldbsearch", "-H", "ldap://"+r.Cfg.JoinDC, "-s", "base", "-b", "", "currentTime").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reading the time of %s (rootDSE): %v: %s", r.Cfg.JoinDC, err, strings.TrimSpace(string(out)))
	}
	m := currentTimeRE.FindStringSubmatch(string(out))
	if m == nil {
		return fmt.Errorf("%s returned no currentTime", r.Cfg.JoinDC)
	}
	t, err := time.Parse("20060102150405", m[1])
	if err != nil {
		return err
	}
	skew := time.Since(t)
	if skew < 0 {
		skew = -skew
	}
	if skew > 2*time.Minute {
		return fmt.Errorf("this host's clock differs from %s by %s: fix the time on both hosts before joining (Kerberos)", r.Cfg.JoinDC, skew.Round(time.Second))
	}
	r.logf("clock skew with %s: %s", r.Cfg.JoinDC, skew.Round(time.Second))
	return nil
}

var dnRE = regexp.MustCompile(`(?m)^defaultNamingContext: (.+)$`)

// checkStaleDC refuses to join under the name of an existing computer (a
// stale DC object from a lost host must be removed first, restore.md 2).
func (r *Runner) checkStaleDC(ctx context.Context, env []string) error {
	c := r.Cfg
	out, err := exec.CommandContext(ctx, "/usr/bin/ldbsearch", "-H", "ldap://"+c.JoinDC, "-s", "base", "-b", "", "defaultNamingContext").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reading the rootDSE of %s: %v", c.JoinDC, err)
	}
	m := dnRE.FindStringSubmatch(string(out))
	if m == nil {
		return fmt.Errorf("%s returned no defaultNamingContext", c.JoinDC)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ldbsearch", "-H", "ldap://"+c.JoinDC, "-U", c.Realm+`\`+c.JoinUser, "-k", "no",
		"-b", strings.TrimSpace(m[1]), "(sAMAccountName="+strings.ToUpper(c.Hostname)+"$)", "dn", "userAccountControl")
	cmd.Env = append(os.Environ(), env...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("checking for an existing computer %s$ on %s: %v: %s", strings.ToUpper(c.Hostname), c.JoinDC, err, strings.TrimSpace(string(out)))
	}
	if strings.Contains(string(out), "\ndn: ") || strings.HasPrefix(string(out), "dn: ") {
		return fmt.Errorf("the domain already has a computer named %s (a stale DC from a lost host?): remove it first "+
			"(samba-tool domain demote --remove-other-dead-server=%s, restore.md section 2) or pick another SC_HOSTNAME",
			strings.ToUpper(c.Hostname), c.Hostname)
	}
	return nil
}

var backupIDRE = regexp.MustCompile(`(?m)Restored backup (\S+)`)

// restore recovers the whole forest from a conductor-backup archive into
// this container. The restored tree stays where samba-tool wrote it, on the
// data volume; /etc/samba/smb.conf is its copy with the image's options.
func (r *Runner) restore(ctx context.Context, st *state.State) error {
	c := r.Cfg
	identity := filepath.Join(SecretsDir, "age-identity")
	if _, err := os.Stat(identity); err != nil {
		return fmt.Errorf("SC_MODE=restore needs the age-identity secret (the operator's offline key): %w", err)
	}
	if _, err := os.Stat(c.RestoreConf); err != nil {
		return fmt.Errorf("SC_MODE=restore needs the backup configuration %s (bucket, the DC's public signing key): %w", c.RestoreConf, err)
	}
	args := []string{"restore", c.RestoreBackup, "--config", c.RestoreConf, "--identity", identity, "--target", RestoreTarget,
		"--newservername", strings.ToUpper(c.Hostname), "--host-ip", c.HostIP}
	r.logf("restoring backup %s of %s as DC %s (SC_RESTORE_CONFIRM=%s)", c.RestoreBackup, c.Realm, c.FQDN(), r.Confirm)
	var log strings.Builder
	cmd := exec.CommandContext(ctx, "/usr/bin/conductor-backup", args...)
	cmd.Env = append(os.Environ(), "CREDENTIALS_DIRECTORY="+SecretsDir)
	cmd.Stdout, cmd.Stderr = &prefixWriter{w: r.Out, name: "conductor-backup", copy: &log}, &prefixWriter{w: r.Out, name: "conductor-backup", copy: &log}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("conductor-backup restore: %w", err)
	}
	sambaDir := filepath.Join(RestoreTarget, "samba")
	st.SmbConf = filepath.Join(sambaDir, "etc", "smb.conf")
	st.PrivateDir = privateDirOf(st.SmbConf)
	if m := backupIDRE.FindStringSubmatch(log.String()); m != nil {
		st.RestoredFrom = m[1]
	}
	if v, _ := smbParam(st.SmbConf, "workgroup"); v != "" {
		st.Domain = strings.ToUpper(v)
	}
	return r.ensureTLS(st.PrivateDir)
}

// prefixWriter prefixes each line written to it.
type prefixWriter struct {
	w    interface{ Write([]byte) (int, error) }
	name string
	copy *strings.Builder
	buf  []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := strings.IndexByte(string(p.buf), '\n')
		if i < 0 {
			break
		}
		line := string(p.buf[:i])
		p.buf = p.buf[i+1:]
		if p.copy != nil {
			p.copy.WriteString(line + "\n")
		}
		if _, err := fmt.Fprintf(p.w, "[%s] %s\n", p.name, line); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}
