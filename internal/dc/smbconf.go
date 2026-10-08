package dc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// managedOptions are the [global] parameters the image sets itself, from
// the configuration. They are passed at provision and join time and written
// into smb.conf at every start, so smb.conf never drifts from the
// environment (for example after SC_HOST_IP changes, or in a restored
// configuration that came from another host).
func (c *Config) managedOptions() map[string]string {
	o := map[string]string{
		"ad dc functional level":        c.FunctionLevel,
		"rpc server dynamic port range": c.RPCPorts,
		"disable netbios":               "yes",
		"tls enabled":                   "yes",
		"tls keyfile":                   "tls/key.pem",
		"tls certfile":                  "tls/cert.pem",
		"tls cafile":                    "tls/ca.pem",
		// NT ACLs (sysvol) in user.NTACL: writing security.* needs
		// CAP_SYS_ADMIN, which the container never gets. Only root in the
		// container (and root on the host) can write the volume.
		"acl_xattr:security_acl_name": "user.NTACL",
	}
	if len(c.Forwarders) > 0 {
		o["dns forwarder"] = strings.Join(c.Forwarders, " ")
	}
	// samba_dnsupdate registers the DC's records through samba-tool (DNS
	// RPC) instead of nsupdate, which the image does not ship.
	o["dns update command"] = "/usr/sbin/samba_dnsupdate --use-samba-tool"
	switch c.NetworkMode {
	case "bridge":
		// Behind published ports: DNS records must carry the host's
		// address, not the container's.
		o["dns update command"] = "/usr/sbin/samba_dnsupdate --use-samba-tool --current-ip=" + c.HostIP
	case "host":
		// Only the advertised address and loopback, so the host's other
		// services (systemd-resolved's stub on 127.0.0.53, libvirt's DNS)
		// keep their ports.
		ifs := c.HostIP
		if c.HostIP6 != "" {
			ifs += " " + c.HostIP6
		}
		o["interfaces"] = ifs + " lo"
		o["bind interfaces only"] = "yes"
	}
	return o
}

// ownedKeys are the parameters the image sets in some configurations: they
// are removed from [global] when the current configuration does not set
// them (a restored smb.conf from a host-networking DC carries "interfaces"
// that would bind a bridged DC to an address it does not have).
var ownedKeys = []string{"interfaces", "bind interfaces only", "dns update command", "dns forwarder"}

// managedKeys are refused in SC_EXTRA_SMB_CONF (the image owns them) in
// addition to the identity of the DC.
var refusedExtra = []string{
	"ad dc functional level", "rpc server dynamic port range", "disable netbios", "tls enabled", "tls keyfile",
	"tls certfile", "tls cafile", "tls crlfile", "acl_xattr:security_acl_name", "dns forwarder", "dns update command",
	"interfaces", "bind interfaces only", "server role", "realm", "workgroup", "netbios name", "private dir",
	"state directory", "cache directory", "lock dir", "binddns dir", "include", "config file", "ntp signd socket directory",
	"vfs objects",
}

// normKey normalizes a parameter name the way Samba compares them
// (case-insensitive, spaces ignored).
func normKey(k string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), " ", ""))
}

// provisionOptions returns --option=... arguments in a stable order.
func (c *Config) provisionOptions() []string {
	o := c.managedOptions()
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, "--option="+k+" = "+o[k])
	}
	return out
}

// applyGlobal rewrites smb.conf so that its [global] section carries exactly
// the given values for these keys (other lines are kept as they are).
func applyGlobal(path string, set map[string]string, extraInclude string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	drop := map[string]bool{}
	for k := range set {
		drop[normKey(k)] = true
	}
	for _, k := range ownedKeys {
		drop[normKey(k)] = true
	}
	if extraInclude != "" {
		drop[normKey("include")] = true
	}
	var out []string
	inGlobal, done := false, false
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inGlobal = strings.EqualFold(t, "[global]")
			out = append(out, line)
			if inGlobal && !done {
				for _, k := range keys {
					out = append(out, "\t"+k+" = "+set[k])
				}
				done = true
			}
			continue
		}
		if inGlobal {
			if k, _, ok := strings.Cut(t, "="); ok && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") && drop[normKey(k)] {
				continue
			}
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("%s has no [global] section", path)
	}
	// The include goes last in [global], after everything it may extend.
	if extraInclude != "" {
		res := make([]string, 0, len(out)+1)
		inGlobal = false
		inserted := false
		for _, l := range out {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "[") {
				if inGlobal && !inserted {
					for len(res) > 0 && strings.TrimSpace(res[len(res)-1]) == "" {
						res = res[:len(res)-1]
					}
					res = append(res, "\tinclude = "+extraInclude, "")
					inserted = true
				}
				inGlobal = strings.EqualFold(t, "[global]")
			}
			res = append(res, l)
		}
		if !inserted {
			res = append(res, "\tinclude = "+extraInclude)
		}
		out = res
	}
	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

// prepareExtra validates SC_EXTRA_SMB_CONF and copies it next to smb.conf.
// It returns the path to include, or "" when there is none.
func (c *Config) prepareExtra() (string, error) {
	if c.ExtraSmbConf == "" {
		_ = os.Remove(ExtraConf)
		return "", nil
	}
	b, err := os.ReadFile(c.ExtraSmbConf)
	if err != nil {
		return "", fmt.Errorf("SC_EXTRA_SMB_CONF: %w", err)
	}
	if err := validateExtra(string(b)); err != nil {
		return "", fmt.Errorf("SC_EXTRA_SMB_CONF %s: %w", c.ExtraSmbConf, err)
	}
	if err := writeFileAtomic(ExtraConf, b, 0o644); err != nil {
		return "", err
	}
	return ExtraConf, nil
}

// validateExtra accepts only [global] parameters (no section header) that
// the image does not set itself.
func validateExtra(s string) error {
	refused := map[string]bool{}
	for _, k := range refusedExtra {
		refused[normKey(k)] = true
	}
	for i, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") {
			return fmt.Errorf("line %d: section headers are not allowed (the file extends [global])", i+1)
		}
		if strings.HasSuffix(t, "\\") {
			return fmt.Errorf("line %d: continuation lines are not allowed", i+1)
		}
		k, _, ok := strings.Cut(t, "=")
		if !ok {
			return fmt.Errorf("line %d: expected name = value", i+1)
		}
		if refused[normKey(k)] {
			return fmt.Errorf("line %d: %q is set by the image (see SC_* variables) and cannot be overridden", i+1, strings.TrimSpace(k))
		}
	}
	return nil
}

// smbParam reads one parameter from an smb.conf the simple way: the value
// of the last "key = value" line in [global] (enough for the paths that
// make_smbconf writes).
func smbParam(path, key string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	want := normKey(key)
	inGlobal := false
	val := ""
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inGlobal = strings.EqualFold(t, "[global]")
			continue
		}
		if !inGlobal {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok && normKey(k) == want {
			val = strings.TrimSpace(v)
		}
	}
	return val, nil
}

// privateDirOf returns the private directory smb.conf names (default the
// image's).
func privateDirOf(smbConf string) string {
	if v, err := smbParam(smbConf, "private dir"); err == nil && v != "" {
		return filepath.Clean(v)
	}
	return DefaultPrivate
}
