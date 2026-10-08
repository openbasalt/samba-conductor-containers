package dc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-containers/internal/state"
)

// Health is `sc-dc-init health`: exit status 0 when the DC serves, with
// warnings that do not fail the check.
func Health(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := state.Load(StateFile)
	if err != nil {
		return fmt.Errorf("no domain yet: %w", err)
	}
	if st.Phase != state.PhaseComplete {
		return errors.New("the first boot has not finished")
	}
	var problems []string
	for _, p := range []string{"53", "88", "389", "636"} {
		if !portOpen("127.0.0.1:" + p) {
			problems = append(problems, "port "+p+" is not answering")
		}
	}
	ldapi := "ldapi://" + url.PathEscape(filepath.Join(st.PrivateDir, "ldapi"))
	if o, err := exec.CommandContext(ctx, "/usr/bin/ldbsearch", "-H", ldapi, "-s", "base", "-b", "", "dnsHostName").CombinedOutput(); err != nil ||
		!strings.Contains(string(o), "dnsHostName:") {
		problems = append(problems, "LDAP rootDSE over ldapi does not answer")
	}
	if fi, err := os.Stat(HelperRunDir + "/helper.sock"); err != nil || fi.Mode()&os.ModeSocket == 0 {
		problems = append(problems, "conductor-helper's socket is missing")
	}
	if b, err := os.ReadFile(RunDir + "/children.json"); err == nil {
		var m map[string]int
		if json.Unmarshal(b, &m) == nil {
			for name, pid := range m {
				if !alive(pid) {
					problems = append(problems, name+" is not running")
				}
			}
		}
	} else {
		problems = append(problems, "the supervisor status is missing")
	}
	// Warnings.
	if synced, known := clockSynced(); known && !synced {
		fmt.Fprintln(out, "warning: the host's kernel clock is not synchronized")
	}
	if _, err := os.Stat(InitialPasswordFile); err == nil {
		fmt.Fprintln(out, "warning: the generated Administrator password is still on the volume (sc-dc-init forget-initial-password)")
	}
	if b, err := os.ReadFile(RunDir + "/dbcheck.txt"); err == nil {
		first, _, _ := strings.Cut(string(b), "\n")
		if first != "ok" {
			fmt.Fprintln(out, "warning: dbcheck after the Samba upgrade:", first)
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	fmt.Fprintf(out, "ok: %s (%s), Samba %s\n", st.Hostname+"."+strings.ToLower(st.Realm), st.Mode, st.SambaVersion)
	return nil
}

// alive reports whether pid runs and is not a zombie.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i > 0 && len(s) > i+2 && s[i+2] != 'Z'
}

// ShowInitialPassword prints the generated Administrator password.
func ShowInitialPassword(out io.Writer) error {
	b, err := os.ReadFile(InitialPasswordFile)
	if err != nil {
		return fmt.Errorf("no generated password: %w (it was given as the admin-password secret, or already forgotten)", err)
	}
	_, err = out.Write(b)
	return err
}

// ForgetInitialPassword deletes the generated password file.
func ForgetInitialPassword(out io.Writer) error {
	if err := os.Remove(InitialPasswordFile); err != nil {
		return err
	}
	fmt.Fprintln(out, "removed", InitialPasswordFile)
	return nil
}

// accountKinds are the service accounts `sc-dc-init account` creates:
// default name, secret file, description.
var accountKinds = map[string][3]string{
	"idp":    {"svc-conductor-idp", "idp-ad-password", "conductor-idp directory reads (no rights)"},
	"sync":   {"svc-conductor-sync", "sync-ad-password", "conductor-sync source reads (no rights)"},
	"backup": {"svc-conductor-backup", "backup-account", "conductor-helper online backups (replication rights only)"},
}

// accountScript creates or updates the account through Samba's Python
// bindings; the password is read from a file, never argv or environment.
const accountScript = `
import os, sys
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
name, pwfile, desc = sys.argv[1], sys.argv[2], sys.argv[3]
pw = open(pwfile).read().rstrip("\r\n")
if not pw:
    sys.exit("the password file is empty")
lp = LoadParm(); lp.load_default()
s = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
r = s.search(base=s.domain_dn(), expression="(sAMAccountName=%s)" % name, attrs=["objectSid"])
if not r:
    s.newuser(name, pw, description=desc)
    print("created " + name)
else:
    s.setpassword("(sAMAccountName=%s)" % name, pw)
    print("updated the password of " + name)
r = s.search(base=s.domain_dn(), expression="(sAMAccountName=%s)" % name, attrs=["objectSid"])
print("SID " + s.schema_format_value("objectSid", r[0]["objectSid"][0]).decode())
print("BASE " + str(s.domain_dn()))
`

// Account creates (or sets the password of) a service account. For
// "backup" it also grants the three replication rights on every naming
// context, and nothing else.
func Account(ctx context.Context, out io.Writer, kind, name, pwFile string) error {
	k, ok := accountKinds[kind]
	if !ok {
		return fmt.Errorf("unknown account kind %q (idp, sync or backup)", kind)
	}
	if name == "" {
		name = k[0]
	}
	if pwFile == "" {
		pwFile = filepath.Join(SecretsDir, k[1])
	}
	if !accountRE.MatchString(name) {
		return fmt.Errorf("%q is not an account name", name)
	}
	if _, err := os.Stat(pwFile); err != nil {
		return fmt.Errorf("the password file: %w", err)
	}
	o, err := exec.CommandContext(ctx, "/usr/bin/python3", "-c", accountScript, name, pwFile, k[2]).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(o)))
	}
	var sid, base string
	for _, l := range strings.Split(string(o), "\n") {
		switch {
		case strings.HasPrefix(l, "SID "):
			sid = strings.TrimPrefix(l, "SID ")
		case strings.HasPrefix(l, "BASE "):
			base = strings.TrimPrefix(l, "BASE ")
		case l != "":
			fmt.Fprintln(out, l)
		}
	}
	if o, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "user", "setexpiry", name, "--noexpiry").CombinedOutput(); err != nil {
		return fmt.Errorf("setexpiry: %v: %s", err, strings.TrimSpace(string(o)))
	}
	if kind != "backup" {
		return nil
	}
	if sid == "" || base == "" {
		return errors.New("could not read the account's SID")
	}
	// DS-Replication-Get-Changes, -Get-Changes-All, -Get-Changes-In-Filtered-Set.
	ace := fmt.Sprintf("(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;%[1]s)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;%[1]s)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;%[1]s)", sid)
	for _, nc := range []string{base, "CN=Configuration," + base, "CN=Schema,CN=Configuration," + base, "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		cur, _ := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dsacl", "get", "--objectdn="+nc).CombinedOutput()
		if strings.Contains(string(cur), "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;"+sid) {
			continue
		}
		if o, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dsacl", "set", "--objectdn="+nc, "--sddl="+ace).CombinedOutput(); err != nil {
			return fmt.Errorf("dsacl on %s: %v: %s", nc, err, strings.TrimSpace(string(o)))
		}
	}
	fmt.Fprintf(out, "%s holds the replication rights on the five naming contexts (%s)\n", name, sid)
	return nil
}

// DNSName adds NAME.<domain> A <SC_HOST_IP> (for the web services of the
// stack: conductor, idp), with the DC's machine account.
func DNSName(ctx context.Context, out io.Writer, c *Config, names []string) error {
	st, err := state.Load(StateFile)
	if err != nil {
		return err
	}
	domain := strings.ToLower(st.Realm)
	ip := c.HostIP
	if ip == "" {
		return errors.New("SC_HOST_IP is not set")
	}
	for _, n := range names {
		if !hostnameRE.MatchString(n) {
			return fmt.Errorf("%q is not a host name label", n)
		}
		q := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dns", "query", "127.0.0.1", domain, n, "A", "-P")
		if o, err := q.CombinedOutput(); err == nil && strings.Contains(string(o), ip) {
			fmt.Fprintf(out, "%s.%s A %s exists\n", n, domain, ip)
			continue
		}
		if o, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dns", "add", "127.0.0.1", domain, n, "A", ip, "-P").CombinedOutput(); err != nil {
			return fmt.Errorf("dns add %s: %v: %s", n, err, strings.TrimSpace(string(o)))
		}
		fmt.Fprintf(out, "added %s.%s A %s\n", n, domain, ip)
	}
	return nil
}
