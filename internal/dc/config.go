// Package dc is sc-dc-init: the entry point (PID 1) of the Samba AD DC
// container. It decides from the state file on the volume whether this
// start provisions, joins, restores or just runs the domain, refuses
// anything that could start a second identity over an existing one, and
// supervises chronyd, samba and conductor-helper.
package dc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

// Paths inside the DC image.
const (
	SambaDir       = "/var/lib/samba"
	DefaultPrivate = SambaDir + "/private"
	SmbConfDir     = "/etc/samba"
	DefaultSmbConf = SmbConfDir + "/smb.conf"
	// StateFile lives at the root of the data volume (not in private/: a
	// restore creates its own private directory).
	StateFile = SambaDir + "/samba-conductor-container.json"
	// CADir keeps the self-signed CA (key 0600) on the data volume.
	CADir = SambaDir + "/sc-ca"
	// InitialPasswordFile holds a generated Administrator password.
	InitialPasswordFile = SambaDir + "/initial-admin-password"
	// PreUpgradeDir keeps the copy taken before a Samba minor upgrade.
	PreUpgradeDir = SambaDir + "/pre-upgrade"
	// RestoreTarget is where a restore writes the restored tree.
	RestoreTarget = SambaDir + "/restore"
	PublicDir     = "/var/lib/sc-public"
	// IssuedDir receives the web certificates the self-signed CA issues
	// for conductor and conductor-idp (mounted only into the setup
	// one-shots).
	IssuedDir    = "/var/lib/sc-issued"
	RunDir       = "/run/sc"
	SecretsDir   = "/run/secrets"
	HelperRunDir = "/run/conductor-helper"
	// ImageInfo is written at build time: versions of what the image holds.
	ImageInfo  = "/usr/share/samba-conductor/image.env"
	ChronyConf = "/usr/share/samba-conductor/chrony.conf"
	ExtraConf  = SmbConfDir + "/sc-extra.conf"
)

// Config is the non-secret configuration (environment).
type Config struct {
	Mode          string
	Realm         string // upper case
	Domain        string // NetBIOS name, upper case
	Hostname      string // short host name, lower case
	HostIP        string
	HostIP6       string
	NetworkMode   string
	Forwarders    []string
	FunctionLevel string
	RPCPorts      string
	JoinDC        string
	JoinUser      string
	RestoreBackup string
	RestoreConf   string
	TLS           string
	Backup        bool
	BackupAccount string
	NTP           bool
	ExtraSmbConf  string

	RetryFirstBoot     bool
	AllowUnsyncedClock bool
	AllowSambaUpgrade  string
}

// Allowed lists every SC_* variable sc-dc-init knows.
var Allowed = []string{
	"SC_MODE", "SC_REALM", "SC_DOMAIN", "SC_HOSTNAME", "SC_HOST_IP", "SC_HOST_IP6", "SC_NETWORK_MODE",
	"SC_DNS_FORWARDERS", "SC_FUNCTION_LEVEL", "SC_RPC_PORTS", "SC_JOIN_DC", "SC_JOIN_USER",
	"SC_RESTORE_BACKUP", "SC_RESTORE_CONFIRM", "SC_RESTORE_CONFIG", "SC_TLS", "SC_BACKUP", "SC_BACKUP_ACCOUNT",
	"SC_NTP", "SC_EXTRA_SMB_CONF", "SC_RETRY_FIRST_BOOT", "SC_ALLOW_UNSYNCED_CLOCK", "SC_ALLOW_SAMBA_UPGRADE",
}

// SecretHint tells where secrets go instead of the environment.
const SecretHint = "put it in a file under /run/secrets (compose secrets:), see the containers documentation"

var (
	realmRE    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))+$`)
	netbiosRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
	hostnameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,14}$`)
	levelRE    = regexp.MustCompile(`^(2008_R2|2012|2012_R2|2016)$`)
	portsRE    = regexp.MustCompile(`^([0-9]{4,5})-([0-9]{4,5})$`)
	accountRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)
)

// Load reads and validates the configuration. The confirm value of a
// restore is returned separately (it is checked against the realm).
func Load(e envcfg.Env) (*Config, string, error) {
	if err := e.Check(Allowed, SecretHint); err != nil {
		return nil, "", err
	}
	var errs []error
	c := &Config{}
	var err error
	if c.Mode, err = e.OneOf("SC_MODE", "run", "provision", "join", "restore", "run"); err != nil {
		errs = append(errs, err)
	}
	c.Realm = strings.ToUpper(e.Get("SC_REALM", ""))
	if c.Realm != "" && !realmRE.MatchString(c.Realm) {
		errs = append(errs, fmt.Errorf("SC_REALM=%q is not a DNS domain name", c.Realm))
	}
	c.Domain = strings.ToUpper(e.Get("SC_DOMAIN", ""))
	if c.Domain != "" && !netbiosRE.MatchString(c.Domain) {
		errs = append(errs, fmt.Errorf("SC_DOMAIN=%q: a NetBIOS name has 1 to 15 letters, digits or hyphens", c.Domain))
	}
	c.Hostname = strings.ToLower(e.Get("SC_HOSTNAME", ""))
	if c.Hostname != "" && !hostnameRE.MatchString(c.Hostname) {
		errs = append(errs, fmt.Errorf("SC_HOSTNAME=%q: a DC host name has 1 to 15 letters, digits or hyphens", c.Hostname))
	}
	c.HostIP = e.Get("SC_HOST_IP", "")
	if c.HostIP != "" {
		if ip := net.ParseIP(c.HostIP); ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			errs = append(errs, fmt.Errorf("SC_HOST_IP=%q: an IPv4 address of this host (not loopback)", c.HostIP))
		}
	}
	c.HostIP6 = e.Get("SC_HOST_IP6", "")
	if c.HostIP6 != "" {
		if ip := net.ParseIP(c.HostIP6); ip == nil || ip.To4() != nil {
			errs = append(errs, fmt.Errorf("SC_HOST_IP6=%q: an IPv6 address", c.HostIP6))
		}
	}
	if c.NetworkMode, err = e.OneOf("SC_NETWORK_MODE", "bridge", "bridge", "host", "macvlan"); err != nil {
		errs = append(errs, err)
	}
	for _, f := range strings.Fields(e.Get("SC_DNS_FORWARDERS", "")) {
		if net.ParseIP(f) == nil {
			errs = append(errs, fmt.Errorf("SC_DNS_FORWARDERS: %q is not an IP address", f))
		} else if f == "127.0.0.11" {
			errs = append(errs, errors.New("SC_DNS_FORWARDERS: 127.0.0.11 is Docker's embedded resolver, which exists only inside a container namespace; name an upstream resolver"))
		}
		c.Forwarders = append(c.Forwarders, f)
	}
	c.FunctionLevel = e.Get("SC_FUNCTION_LEVEL", "2016")
	if !levelRE.MatchString(c.FunctionLevel) {
		errs = append(errs, fmt.Errorf("SC_FUNCTION_LEVEL=%q: 2008_R2, 2012, 2012_R2 or 2016", c.FunctionLevel))
	}
	c.RPCPorts = e.Get("SC_RPC_PORTS", "49152-49159")
	if m := portsRE.FindStringSubmatch(c.RPCPorts); m == nil || atoi(m[1]) < 1024 || atoi(m[1]) >= atoi(m[2]) || atoi(m[2]) > 65535 {
		errs = append(errs, fmt.Errorf("SC_RPC_PORTS=%q: a range such as 49152-49159", c.RPCPorts))
	}
	c.JoinDC = e.Get("SC_JOIN_DC", "")
	if c.JoinDC != "" && net.ParseIP(c.JoinDC) == nil {
		// An address: the container resolves through itself, which cannot
		// answer before the join.
		errs = append(errs, fmt.Errorf("SC_JOIN_DC=%q: the IP address of an existing DC", c.JoinDC))
	}
	c.JoinUser = e.Get("SC_JOIN_USER", "Administrator")
	if !accountRE.MatchString(c.JoinUser) {
		errs = append(errs, fmt.Errorf("SC_JOIN_USER=%q is not an account name", c.JoinUser))
	}
	c.RestoreBackup = e.Get("SC_RESTORE_BACKUP", "latest")
	if strings.ContainsAny(c.RestoreBackup, "/\\ ") {
		errs = append(errs, fmt.Errorf("SC_RESTORE_BACKUP=%q: a backup ID or latest", c.RestoreBackup))
	}
	c.RestoreConf = e.Get("SC_RESTORE_CONFIG", "/etc/sc/restore/conductor-backup.toml")
	if c.TLS, err = e.OneOf("SC_TLS", "self-signed", "self-signed", "provided"); err != nil {
		errs = append(errs, err)
	}
	if c.Backup, err = e.Bool("SC_BACKUP", false); err != nil {
		errs = append(errs, err)
	}
	c.BackupAccount = e.Get("SC_BACKUP_ACCOUNT", "svc-conductor-backup")
	if !accountRE.MatchString(c.BackupAccount) {
		errs = append(errs, fmt.Errorf("SC_BACKUP_ACCOUNT=%q is not an account name", c.BackupAccount))
	}
	if c.NTP, err = e.Bool("SC_NTP", true); err != nil {
		errs = append(errs, err)
	}
	c.ExtraSmbConf = e.Get("SC_EXTRA_SMB_CONF", "")
	if c.RetryFirstBoot, err = e.Bool("SC_RETRY_FIRST_BOOT", false); err != nil {
		errs = append(errs, err)
	}
	if c.AllowUnsyncedClock, err = e.Bool("SC_ALLOW_UNSYNCED_CLOCK", false); err != nil {
		errs = append(errs, err)
	}
	c.AllowSambaUpgrade = e.Get("SC_ALLOW_SAMBA_UPGRADE", "")
	return c, strings.ToUpper(e.Get("SC_RESTORE_CONFIRM", "")), errors.Join(errs...)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// DNSDomain is the lower-case realm.
func (c *Config) DNSDomain() string { return strings.ToLower(c.Realm) }

// FQDN of this DC.
func (c *Config) FQDN() string { return c.Hostname + "." + c.DNSDomain() }

// requireFirstBoot checks what every first boot needs.
func (c *Config) requireFirstBoot(confirm string) error {
	var errs []error
	need := func(v, name string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required for SC_MODE=%s", name, c.Mode))
		}
	}
	need(c.Realm, "SC_REALM")
	need(c.Hostname, "SC_HOSTNAME")
	need(c.HostIP, "SC_HOST_IP")
	switch c.Mode {
	case "provision":
		need(c.Domain, "SC_DOMAIN")
	case "join":
		need(c.JoinDC, "SC_JOIN_DC")
	case "restore":
		if confirm != c.Realm {
			errs = append(errs, fmt.Errorf("SC_RESTORE_CONFIRM must be set to the realm (%s): a full-forest restore must never run while another DC of the domain is running (restore.md)", c.Realm))
		}
	}
	return errors.Join(errs...)
}

// checkHostname refuses a container whose host name differs from
// SC_HOSTNAME (Samba names the DC after the host).
func (c *Config) checkHostname() error {
	h, err := os.Hostname()
	if err != nil {
		return err
	}
	short := strings.ToLower(strings.SplitN(h, ".", 2)[0])
	if c.Hostname != "" && short != c.Hostname {
		return fmt.Errorf("the container's host name is %q but SC_HOSTNAME is %q: set hostname: %s in the compose file", short, c.Hostname, c.Hostname)
	}
	return nil
}
