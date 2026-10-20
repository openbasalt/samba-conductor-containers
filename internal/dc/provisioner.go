package dc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openbasalt/samba-conductor-containers/internal/state"
)

// The delegated account of conductor-provisioner (its docs/delegation.md):
// a member of Domain Users only, marked sensitive (never delegated), with
// access entries on the managed OUs that only user objects below them
// inherit.
const (
	provisionerAccount = "svc-conductor-prov"
	provisionerSecret  = "provisioner-ad-password"
	// classUser is the schema GUID of the user class: the inherited
	// object type of every entry, so only user objects inherit them.
	classUser = "bf967aba-0de6-11d0-a285-00aa003049e2"
)

// provisionerRights are the four entries of invitations and resets:
// Reset Password, and write lockoutTime, pwdLastSet, userAccountControl.
var provisionerRights = []string{
	"OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;" + classUser,
	"OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;" + classUser,
	"OA;CIIO;WP;bf967a0a-0de6-11d0-a285-00aa003049e2;" + classUser,
	"OA;CIIO;WP;bf967a68-0de6-11d0-a285-00aa003049e2;" + classUser,
}

// googleFirstRights are the entries the Google-first plan operations add:
// create user objects (on the OU and the OUs below it), delete user
// objects (a move needs it), and write cn, name and the Google-owned
// attributes and the marker of user objects.
var googleFirstRights = []string{
	"OA;CI;CC;" + classUser + ";",
	"OA;CIIO;SD;;" + classUser,
	"OA;CIIO;WP;bf96793f-0de6-11d0-a285-00aa003049e2;" + classUser, // cn
	"OA;CIIO;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;" + classUser, // name
	"OA;CIIO;WP;f0f8ff8e-1191-11d0-a060-00aa006c33ed;" + classUser, // givenName
	"OA;CIIO;WP;bf967a41-0de6-11d0-a285-00aa003049e2;" + classUser, // sn
	"OA;CIIO;WP;bf967953-0de6-11d0-a285-00aa003049e2;" + classUser, // displayName
	"OA;CIIO;WP;bf967961-0de6-11d0-a285-00aa003049e2;" + classUser, // mail
	"OA;CIIO;WP;bf967a06-0de6-11d0-a285-00aa003049e2;" + classUser, // proxyAddresses
	"OA;CIIO;WP;bf967a55-0de6-11d0-a285-00aa003049e2;" + classUser, // title
	"OA;CIIO;WP;bf96794f-0de6-11d0-a285-00aa003049e2;" + classUser, // department
	"OA;CIIO;WP;bf967962-0de6-11d0-a285-00aa003049e2;" + classUser, // employeeID
	"OA;CIIO;WP;bf967a49-0de6-11d0-a285-00aa003049e2;" + classUser, // telephoneNumber
	"OA;CIIO;WP;f0f8ffa3-1191-11d0-a060-00aa006c33ed;" + classUser, // mobile
	"OA;CIIO;WP;9709eaaf-49da-4db2-908a-0446e5eab844;" + classUser, // msDS-cloudExtensionAttribute1
}

// ProvisionerOptions are the flags of `sc-dc-init account provisioner`.
type ProvisionerOptions struct {
	Name         string
	PasswordFile string
	// OUs are the managed OUs (DNs); empty: OU=People,<domain>.
	OUs []string
	// GoogleFirst adds the rights of the Google-first plan operations.
	GoogleFirst bool
}

// provisionerScript creates or updates the account, marks it sensitive,
// and creates the missing OUs (given top-down); the password is read from
// a file, never argv or environment.
const provisionerScript = `
import sys
from samba import dsdb, ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
name, pwfile, desc = sys.argv[1], sys.argv[2], sys.argv[3]
ous = sys.argv[4:]
pw = open(pwfile).read().rstrip("\r\n")
if not pw:
    sys.exit("the password file is empty")
lp = LoadParm(); lp.load_default()
s = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
flt = "(sAMAccountName=%s)" % name
r = s.search(base=s.domain_dn(), expression=flt, attrs=["objectSid", "memberOf"])
if not r:
    s.newuser(name, pw, description=desc)
    print("created " + name)
else:
    if "memberOf" in r[0]:
        sys.exit("%s is a member of other groups than Domain Users: refusing (docs/delegation.md)" % name)
    s.setpassword(flt, pw)
    print("updated the password of " + name)
s.toggle_userAccountFlags(flt, dsdb.UF_NOT_DELEGATED, on=True, strict=False)
for ou in ous:
    try:
        s.search(base=ou, scope=ldb.SCOPE_BASE, attrs=[])
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        s.create_ou(ou)
        print("created " + ou)
r = s.search(base=s.domain_dn(), expression=flt, attrs=["objectSid"])
print("SID " + s.schema_format_value("objectSid", r[0]["objectSid"][0]).decode())
`

// ouRDNRE is one OU component the stack accepts: plain characters only,
// so a DN never needs escaping on its way to samba-tool or the SDDL.
var ouRDNRE = regexp.MustCompile(`^(?i:ou)=([A-Za-z0-9][A-Za-z0-9 ._-]{0,63})$`)

// ManagedOUs validates managed OU DNs against the domain's base DN and
// returns them normalized ("OU=<name>,...,DC=..."), with the chain of OUs
// to create, top-down. Only OUs below the domain head are accepted, never
// the Domain Controllers OU (conductor-provisioner refuses the containers
// CN=Users, CN=System and the others on its own).
func ManagedOUs(base string, dns []string) (ous, chain []string, err error) {
	seen := map[string]bool{}
	for _, dn := range dns {
		parts := strings.Split(dn, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		baseParts := strings.Split(base, ",")
		if len(parts) <= len(baseParts) ||
			!strings.EqualFold(strings.Join(parts[len(parts)-len(baseParts):], ","), base) {
			return nil, nil, fmt.Errorf("%q is not an OU below %s", dn, base)
		}
		rdns := parts[:len(parts)-len(baseParts)]
		norm := make([]string, len(rdns))
		for i, r := range rdns {
			m := ouRDNRE.FindStringSubmatch(r)
			if m == nil {
				return nil, nil, fmt.Errorf("%q: %q is not an OU name the stack accepts (letters, digits, space, '.', '_', '-')", dn, r)
			}
			if strings.EqualFold(m[1], "Domain Controllers") {
				return nil, nil, fmt.Errorf("%q: the Domain Controllers OU is never a managed OU", dn)
			}
			norm[i] = "OU=" + m[1]
		}
		// Top-down: the OU right below the head first.
		for i := len(norm) - 1; i >= 0; i-- {
			d := strings.Join(norm[i:], ",") + "," + base
			if !seen[strings.ToLower(d)] {
				seen[strings.ToLower(d)] = true
				chain = append(chain, d)
			}
		}
		ous = append(ous, strings.Join(norm, ",")+","+base)
	}
	return ous, chain, nil
}

// realmBase returns DC=... of a realm.
func realmBase(realm string) string {
	return "DC=" + strings.ReplaceAll(strings.ToLower(realm), ".", ",DC=")
}

// ProvisionerAccount creates (or sets the password of) the delegated
// account of conductor-provisioner, marks it sensitive, creates the
// managed OUs that are missing and grants it the access entries on each
// (only those not there yet), and nothing else.
func ProvisionerAccount(ctx context.Context, out io.Writer, o ProvisionerOptions) error {
	name := o.Name
	if name == "" {
		name = provisionerAccount
	}
	if !accountRE.MatchString(name) {
		return fmt.Errorf("%q is not an account name", name)
	}
	pwFile := o.PasswordFile
	if pwFile == "" {
		pwFile = filepath.Join(SecretsDir, provisionerSecret)
	}
	if _, err := os.Stat(pwFile); err != nil {
		return fmt.Errorf("the password file: %w", err)
	}
	st, err := state.Load(StateFile)
	if err != nil {
		return err
	}
	if st.Realm == "" {
		return errors.New("the domain is not set up yet (no realm in the state file)")
	}
	base := realmBase(st.Realm)
	dns := o.OUs
	if len(dns) == 0 {
		dns = []string{"OU=People," + base}
	}
	ous, chain, err := ManagedOUs(base, dns)
	if err != nil {
		return err
	}
	args := append([]string{"-c", provisionerScript, name, pwFile, "conductor-provisioner delegated account"}, chain...)
	o2, err := exec.CommandContext(ctx, "/usr/bin/python3", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(o2)))
	}
	sid := ""
	for _, l := range strings.Split(string(o2), "\n") {
		switch {
		case strings.HasPrefix(l, "SID "):
			sid = strings.TrimPrefix(l, "SID ")
		case l != "":
			fmt.Fprintln(out, l)
		}
	}
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return errors.New("could not read the account's SID")
	}
	if o, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "user", "setexpiry", name, "--noexpiry").CombinedOutput(); err != nil {
		return fmt.Errorf("setexpiry: %v: %s", err, strings.TrimSpace(string(o)))
	}
	rights := provisionerRights
	if o.GoogleFirst {
		rights = append(append([]string(nil), provisionerRights...), googleFirstRights...)
	}
	for _, ou := range ous {
		cur, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dsacl", "get", "--objectdn="+ou).CombinedOutput()
		if err != nil {
			return fmt.Errorf("dsacl get %s: %v: %s", ou, err, strings.TrimSpace(string(cur)))
		}
		missing := MissingEntries(string(cur), rights, sid)
		if len(missing) == 0 {
			fmt.Fprintf(out, "%s: the %d entries of %s are there\n", ou, len(rights), name)
			continue
		}
		if o, err := exec.CommandContext(ctx, "/usr/bin/samba-tool", "dsacl", "set", "--objectdn="+ou, "--sddl="+strings.Join(missing, "")).CombinedOutput(); err != nil {
			return fmt.Errorf("dsacl set %s: %v: %s", ou, err, strings.TrimSpace(string(o)))
		}
		fmt.Fprintf(out, "%s: %d of %d entries added for %s\n", ou, len(missing), len(rights), name)
	}
	fmt.Fprintf(out, "%s (%s) is delegated on %s\n", name, sid, strings.Join(ous, "; "))
	fmt.Fprintf(out, "managed OUs for provisioner-setup: SC_PROVISIONER_OUS=%s\n", strings.Join(ous, ";"))
	return nil
}

// MissingEntries returns the SDDL entries ("(...)") of rights for sid that
// the descriptor text (samba-tool dsacl get) does not hold yet. Each right
// is "OA;<flags>;<rights>;<object type>;<inherited object type>".
func MissingEntries(descriptor string, rights []string, sid string) []string {
	have := strings.ToUpper(descriptor)
	var out []string
	for _, r := range rights {
		e := "(" + r + ";" + sid + ")"
		if !strings.Contains(have, strings.ToUpper(e)) {
			out = append(out, e)
		}
	}
	return out
}
