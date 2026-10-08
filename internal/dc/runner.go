package dc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-containers/internal/state"
	"github.com/openbasalt/samba-conductor-containers/internal/sup"
)

// Runner carries one start of the DC container.
type Runner struct {
	Cfg     *Config
	Confirm string
	Out     io.Writer
	// Image holds the versions written into the image at build time.
	Image map[string]string
}

func (r *Runner) logf(format string, args ...any) {
	fmt.Fprintf(r.Out, "[sc-dc-init] "+format+"\n", args...)
}

// ReadImageInfo reads KEY=VALUE lines of the image's version file.
func ReadImageInfo(path string) map[string]string {
	m := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

// Start is the entry point: first boot when the volume is empty, refusals
// when it is not what the configuration says, then supervision.
func (r *Runner) Start(ctx context.Context) error {
	c := r.Cfg
	if err := c.checkHostname(); err != nil {
		return err
	}
	if err := os.MkdirAll(RunDir, 0o700); err != nil {
		return err
	}
	st, err := state.Load(StateFile)
	switch {
	case errors.Is(err, state.ErrNone):
		empty, what, eerr := volumesEmpty()
		if eerr != nil {
			return eerr
		}
		if !empty {
			return fmt.Errorf("the volumes hold Samba data (%s) but no %s: this is not a domain this image created. "+
				"Adopting an existing Samba data directory is not supported; join a new container DC to that domain "+
				"(SC_MODE=join) and demote the old DC, or start with empty volumes", what, filepath.Base(StateFile))
		}
		if c.Mode == "run" {
			return errors.New("the volumes are empty and SC_MODE=run: set SC_MODE=provision (a new domain), join " +
				"(an additional DC of an existing domain) or restore (a full-forest recovery from a conductor-backup archive)")
		}
		if st, err = r.firstBoot(ctx, true); err != nil {
			return err
		}
	case err != nil:
		return err
	case st.Phase == state.PhaseFirstBoot:
		if !c.RetryFirstBoot {
			return fmt.Errorf("a first boot (%s of %s) did not finish. Nothing was started; set SC_RETRY_FIRST_BOOT=1 to wipe "+
				"what it created and start again (only what this init created: the volumes were empty before)", st.Mode, st.Realm)
		}
		if !st.VolumeWasEmpty {
			return errors.New("SC_RETRY_FIRST_BOOT: the first boot did not start on empty volumes; refusing to wipe them")
		}
		if c.Mode == "run" {
			c.Mode = st.Mode
		}
		r.logf("SC_RETRY_FIRST_BOOT: wiping what the unfinished %s created", st.Mode)
		if err := wipeVolumes(); err != nil {
			return err
		}
		if st, err = r.firstBoot(ctx, true); err != nil {
			return err
		}
	default:
		if c.Mode != "run" {
			r.logf("SC_MODE=%s ignored: the volume already holds the domain %s (first boot by %s on %s)", c.Mode, st.Realm,
				st.Mode, st.CreatedAt.Format(time.RFC3339))
		}
		if c.Realm != "" && c.Realm != st.Realm {
			return fmt.Errorf("SC_REALM=%s but the volume holds the domain %s: refusing to start (a wrong volume or a typo must never start a different DC)", c.Realm, st.Realm)
		}
		if c.Hostname != "" && c.Hostname != st.Hostname {
			return fmt.Errorf("SC_HOSTNAME=%s but the volume holds the DC %s: refusing to start", c.Hostname, st.Hostname)
		}
		c.Realm, c.Hostname = st.Realm, st.Hostname
		if c.Domain == "" {
			c.Domain = st.Domain
		}
		if err := c.checkHostname(); err != nil {
			return err
		}
	}
	if c.HostIP == "" {
		return errors.New("SC_HOST_IP is required")
	}
	return r.run(ctx, st)
}

// volumesEmpty reports whether the DC's volumes hold nothing (a fresh
// named volume is empty: the image ships /var/lib/samba and /etc/samba
// empty).
func volumesEmpty() (bool, string, error) {
	for _, d := range []string{SambaDir, SmbConfDir} {
		entries, err := os.ReadDir(d)
		if err != nil {
			return false, "", err
		}
		for _, e := range entries {
			if e.Name() == "lost+found" {
				continue
			}
			return false, filepath.Join(d, e.Name()), nil
		}
	}
	return true, "", nil
}

// wipeVolumes removes everything in the DC volumes (only used for a retry
// of a first boot that started on empty volumes).
func wipeVolumes() error {
	for _, d := range []string{SambaDir, SmbConfDir} {
		entries, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Name() == "lost+found" {
				continue
			}
			if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// firstBoot provisions, joins or restores, recording the state first.
func (r *Runner) firstBoot(ctx context.Context, wasEmpty bool) (*state.State, error) {
	c := r.Cfg
	if err := c.requireFirstBoot(r.Confirm); err != nil {
		return nil, err
	}
	if c.Mode != "restore" {
		if err := checkClock(c.AllowUnsyncedClock); err != nil {
			return nil, err
		}
	}
	st := &state.State{Phase: state.PhaseFirstBoot, Mode: c.Mode, Realm: c.Realm, Domain: c.Domain, Hostname: c.Hostname,
		VolumeWasEmpty: wasEmpty, PrivateDir: DefaultPrivate, SmbConf: DefaultSmbConf,
		ImageVersion: r.Image["IMAGE_VERSION"], ConductorVersion: r.Image["CONDUCTOR_VERSION"]}
	if err := state.Save(StateFile, st); err != nil {
		return nil, err
	}
	var err error
	switch c.Mode {
	case "provision":
		err = r.provision(ctx)
	case "join":
		err = r.join(ctx)
	case "restore":
		err = r.restore(ctx, st)
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed (state left at %q; fix the cause, then SC_RETRY_FIRST_BOOT=1): %w", c.Mode, state.PhaseFirstBoot, err)
	}
	if st.Domain == "" {
		if v, _ := smbParam(st.SmbConf, "workgroup"); v != "" {
			st.Domain = strings.ToUpper(v)
			c.Domain = st.Domain
		}
	}
	st.SambaVersion, _ = sambaVersion(ctx)
	st.Phase = state.PhaseComplete
	if err := state.Save(StateFile, st); err != nil {
		return nil, err
	}
	r.logf("first boot complete: %s of %s, DC %s", c.Mode, c.Realm, c.FQDN())
	return st, nil
}

// run prepares an existing domain and supervises it.
func (r *Runner) run(ctx context.Context, st *state.State) error {
	c := r.Cfg
	upgrade, err := r.checkUpgrade(ctx, st)
	if err != nil {
		return err
	}
	extra, err := c.prepareExtra()
	if err != nil {
		return err
	}
	if err := applyGlobal(st.SmbConf, c.managedOptions(), extra); err != nil {
		return err
	}
	if st.SmbConf != DefaultSmbConf {
		// A restored domain keeps its tree where the restore wrote it; Samba
		// and samba-tool read /etc/samba/smb.conf.
		if err := copyFile(st.SmbConf, DefaultSmbConf, 0o644); err != nil {
			return err
		}
	}
	if err := r.ensureTLS(st.PrivateDir); err != nil {
		return err
	}
	if err := exportKrb5(st.PrivateDir); err != nil {
		return err
	}
	if err := exportClientSmbConf(c.Realm, c.Domain); err != nil {
		return err
	}
	if err := r.writeHelperConfig(); err != nil {
		return err
	}
	if err := prepareRuntime(); err != nil {
		return err
	}
	r.ensureSelfResolver()
	r.startupWarnings(st)
	krb5 := "KRB5_CONFIG=" + filepath.Join(st.PrivateDir, "krb5.conf")
	procs := []sup.Process{}
	if c.NTP {
		procs = append(procs, sup.Process{Name: "chronyd", Path: "/usr/sbin/chronyd",
			// -x: never adjust the clock (no CAP_SYS_TIME): the container
			// serves the host's clock, signed through ntp_signd.
			Args: []string{"-d", "-x", "-u", "_chrony", "-f", ChronyConf}})
	}
	procs = append(procs,
		sup.Process{Name: "samba", Path: "/usr/sbin/samba", Args: []string{"--foreground", "--no-process-group", "--debug-stdout"}, Env: []string{krb5}},
		sup.Process{Name: "conductor-helper", Path: "/usr/bin/conductor-helper", Env: []string{krb5}, Args: []string{
			"--socket", HelperRunDir + "/helper.sock", "--backup-socket", HelperRunDir + "/backup.sock",
			"--allow-user", "conductor", "--samba-tool", "/usr/bin/samba-tool", "--config", RunDir + "/helper.toml"}},
	)
	s := &sup.Supervisor{Out: r.Out, StatusFile: RunDir + "/children.json"}
	return s.Run(ctx, procs, func(bctx context.Context) {
		r.afterStart(bctx, s, st, upgrade)
	})
}

// afterStart waits for Samba, records the versions that now run the
// domain, and runs a read-only dbcheck after an upgrade.
func (r *Runner) afterStart(ctx context.Context, s *sup.Supervisor, st *state.State, upgrade string) {
	deadline := time.Now().Add(5 * time.Minute)
	for !portOpen("127.0.0.1:389") {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	r.logf("Samba answers on 389; DC %s of %s is up", r.Cfg.FQDN(), st.Realm)
	if v, err := sambaVersion(ctx); err == nil {
		st.SambaVersion = v
	}
	st.ImageVersion, st.ConductorVersion = r.Image["IMAGE_VERSION"], r.Image["CONDUCTOR_VERSION"]
	if err := state.Save(StateFile, st); err != nil {
		r.logf("WARNING: saving the state file: %v", err)
	}
	if upgrade == "" {
		return
	}
	r.logf("running samba-tool dbcheck --cross-ncs (read-only) after the Samba upgrade (%s)", upgrade)
	out, err := s.Exec(ctx, "/usr/bin/samba-tool", "dbcheck", "--cross-ncs")
	res := "ok"
	if err != nil {
		res = "errors: " + err.Error()
	}
	_ = os.WriteFile(RunDir+"/dbcheck.txt", []byte(res+"\n"+string(out)), 0o600)
	r.logf("dbcheck after upgrade: %s (details: sc-dc-init health)", res)
}

// prepareRuntime creates what the processes expect on the tmpfs and volume.
func prepareRuntime() error {
	for _, d := range []string{"/run/samba", "/run/chrony", "/var/lib/chrony", "/var/cache/samba", "/var/log/samba"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// chronyd runs as _chrony and reads Samba's ntp_signd socket.
	signd := SambaDir + "/ntp_signd"
	if err := os.MkdirAll(signd, 0o750); err != nil {
		return err
	}
	if gid, err := lookupGroup("_chrony"); err == nil {
		_ = os.Chown(signd, 0, gid)
		_ = os.Chown("/run/chrony", uidOf("_chrony"), gid)
		_ = os.Chown("/var/lib/chrony", uidOf("_chrony"), gid)
		_ = os.Chmod("/run/chrony", 0o750)
	}
	return os.Chmod(signd, 0o750)
}

// ensureSelfResolver makes the DC its own resolver. In bridge mode the
// compose file sets it (dns: 127.0.0.1); with host networking the engine
// gives the container a copy of the host's resolv.conf (and refuses a dns
// option), whose servers usually do not know the domain: then replication
// and samba_dnsupdate cannot find the other DCs. The file is the container's
// own copy, so rewriting it never touches the host. Samba's DNS forwards
// every other name to SC_DNS_FORWARDERS.
func (r *Runner) ensureSelfResolver() {
	const p = "/etc/resolv.conf"
	b, _ := os.ReadFile(p)
	if firstNameserver(string(b)) == "127.0.0.1" {
		return
	}
	want := fmt.Sprintf("search %s\nnameserver 127.0.0.1\n", r.Cfg.DNSDomain())
	if err := os.WriteFile(p, []byte(want), 0o644); err != nil {
		r.logf("WARNING: /etc/resolv.conf does not name the DC itself and cannot be changed (%v): mount a resolv.conf with "+
			"nameserver 127.0.0.1 (addons/host-network.yaml does), or make the resolver it names forward %s to this DC", err, r.Cfg.DNSDomain())
		return
	}
	r.logf("resolver: this DC (127.0.0.1), search %s", r.Cfg.DNSDomain())
}

// firstNameserver returns the first nameserver of a resolv.conf.
func firstNameserver(s string) string {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			return f[1]
		}
	}
	return ""
}

// exportKrb5 publishes the realm's krb5.conf for the other containers.
func exportKrb5(privateDir string) error {
	if _, err := os.Stat(PublicDir); err != nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(privateDir, "krb5.conf"))
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(PublicDir, "krb5.conf"), b, 0o644)
}

// exportClientSmbConf publishes a client smb.conf for samba-tool in the
// conductor container (GPO create and delete reach sysvol over SMB, and
// Samba's SMB client needs a configuration file naming the realm).
func exportClientSmbConf(realm, domain string) error {
	if _, err := os.Stat(PublicDir); err != nil {
		return nil
	}
	conf := fmt.Sprintf("# Written by sc-dc-init: client settings of the domain for samba-tool in\n"+
		"# the other containers (never a server configuration).\n[global]\n\tworkgroup = %s\n\trealm = %s\n"+
		"\tsecurity = ADS\n\tdisable netbios = yes\n", domain, realm)
	return writeFileAtomic(filepath.Join(PublicDir, "smb.conf"), []byte(conf), 0o644)
}

// startupWarnings logs what an operator should fix but does not stop the DC.
func (r *Runner) startupWarnings(st *state.State) {
	if synced, known := clockSynced(); known && !synced {
		r.logf("WARNING: the host's kernel clock is not synchronized; keep the host's clock in sync (chrony, timesyncd): Kerberos fails beyond 5 minutes of skew")
	}
	if _, err := os.Stat(InitialPasswordFile); err == nil {
		r.logf("NOTE: a generated Administrator password is in %s; read it with `sc-dc-init show-initial-password`, then `sc-dc-init forget-initial-password`", InitialPasswordFile)
	}
	for _, s := range []string{"admin-password", "join-password", "age-identity"} {
		if _, err := os.Stat(filepath.Join(SecretsDir, s)); err == nil {
			r.logf("WARNING: the first-boot secret %q is still mounted; remove it from the stack now that the domain exists", s)
		}
	}
	if st.Mode == "restore" {
		r.logf("NOTE: restored domain (backup %s); follow the next steps printed at the restore", st.RestoredFrom)
	}
}

// sambaVersion returns "4.22.11" from `samba --version`.
func sambaVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/samba", "--version").Output()
	if err != nil {
		return "", err
	}
	v, err := parseSambaVersion(string(out))
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b, mode)
}

// runCmd runs a program (before supervision starts) with its output
// prefixed in the log; secrets never appear in args.
func (r *Runner) runCmd(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Fprintf(r.Out, "[%s] %s\n", filepath.Base(name), sc.Text())
		}
	}()
	err := cmd.Run()
	_ = pw.Close()
	<-done
	if err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(firstArgs(args, 3), " "), err)
	}
	return nil
}

func firstArgs(a []string, n int) []string {
	if len(a) > n {
		return a[:n]
	}
	return a
}
