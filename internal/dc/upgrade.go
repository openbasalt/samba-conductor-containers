package dc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openbasalt/samba-conductor-containers/internal/state"
)

// version is a Samba version.
type version struct{ Major, Minor, Patch int }

func (v version) String() string    { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }
func (v version) MinorLine() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

var versionRE = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// parseSambaVersion accepts "Version 4.22.11-Debian-4.22.11+dfsg-0+deb13u1"
// or "4.22.11".
func parseSambaVersion(s string) (version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("no Samba version in %q", strings.TrimSpace(s))
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return version{a, b, c}, nil
}

// upgradeKind classifies the image's Samba against the one that last ran
// the domain: "", "patch", "minor" or "downgrade".
func upgradeKind(was, now version) string {
	switch {
	case now == was:
		return ""
	case now.Major < was.Major || now.Major == was.Major && now.Minor < was.Minor ||
		now.Major == was.Major && now.Minor == was.Minor && now.Patch < was.Patch:
		return "downgrade"
	case now.Major == was.Major && now.Minor == was.Minor:
		return "patch"
	}
	return "minor"
}

// checkUpgrade compares the Samba of this image with the one that last ran
// the domain. A patch update starts (and runs a read-only dbcheck once Samba
// is up); a minor update needs SC_ALLOW_SAMBA_UPGRADE=<new minor> and takes
// an offline copy first; a downgrade is refused. It returns a description
// of the upgrade ("" when there is none).
func (r *Runner) checkUpgrade(ctx context.Context, st *state.State) (string, error) {
	if st.SambaVersion == "" {
		return "", nil
	}
	nowS, err := sambaVersion(ctx)
	if err != nil {
		return "", err
	}
	was, err := parseSambaVersion(st.SambaVersion)
	if err != nil {
		return "", err
	}
	now, _ := parseSambaVersion(nowS)
	desc := fmt.Sprintf("%s -> %s", was, now)
	switch upgradeKind(was, now) {
	case "":
		return "", nil
	case "downgrade":
		return "", fmt.Errorf("this image has Samba %s but the domain was last run by Samba %s: downgrades are not supported "+
			"(use an image with Samba %s or newer; a copy taken before the last minor upgrade, if any, is in %s)", now, was, was, PreUpgradeDir)
	case "patch":
		r.logf("Samba patch update %s", desc)
		return desc, nil
	}
	if r.Cfg.AllowSambaUpgrade != now.MinorLine() {
		return "", fmt.Errorf("this image has Samba %s but the domain was last run by Samba %s: a minor upgrade is deliberate. "+
			"Take a conductor-backup run, then set SC_ALLOW_SAMBA_UPGRADE=%s to upgrade (an offline copy of private/ and sysvol/ is taken first)",
			now, was, now.MinorLine())
	}
	if err := r.preUpgradeCopy(ctx, st, was); err != nil {
		return "", fmt.Errorf("the copy before the Samba upgrade failed, nothing was started: %w", err)
	}
	r.logf("Samba minor upgrade %s acknowledged (SC_ALLOW_SAMBA_UPGRADE=%s)", desc, r.Cfg.AllowSambaUpgrade)
	return desc, nil
}

// preUpgradeCopy writes private/ and sysvol/ (with their extended
// attributes, which carry the NT ACLs) into pre-upgrade/<old>.tar, keeping
// only the newest copy.
func (r *Runner) preUpgradeCopy(ctx context.Context, st *state.State, was version) error {
	if err := os.MkdirAll(PreUpgradeDir, 0o700); err != nil {
		return err
	}
	stateDir := filepath.Dir(st.PrivateDir)
	if v, _ := smbParam(st.SmbConf, "state directory"); v != "" {
		stateDir = v
	}
	sysvol := filepath.Join(stateDir, "sysvol")
	dst := filepath.Join(PreUpgradeDir, was.String()+".tar")
	tmp := dst + ".part"
	_ = os.Remove(tmp)
	args := []string{"--xattrs", "--xattrs-include=*", "--acls", "-cf", tmp, "-C", "/",
		strings.TrimPrefix(st.PrivateDir, "/"), strings.TrimPrefix(sysvol, "/")}
	r.logf("copying %s and %s to %s", st.PrivateDir, sysvol, dst)
	if out, err := exec.CommandContext(ctx, "tar", args...).CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("tar: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	entries, _ := os.ReadDir(PreUpgradeDir)
	for _, e := range entries {
		if p := filepath.Join(PreUpgradeDir, e.Name()); p != dst {
			_ = os.RemoveAll(p)
		}
	}
	return nil
}
