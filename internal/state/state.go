// Package state is the DC container's state file: what the first boot did
// and which domain lives on the volume. It is the only thing that decides
// whether a start provisions, joins, restores or just runs.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Phases of the state file.
const (
	// PhaseFirstBoot is written before the first boot touches anything; a
	// state file still in this phase means a first boot died half-way.
	PhaseFirstBoot = "first-boot"
	// PhaseComplete means the domain on the volume is ready to run.
	PhaseComplete = "complete"
)

// State is the JSON document.
type State struct {
	Phase string `json:"phase"`
	// Mode used for the first boot: provision, join or restore.
	Mode     string `json:"mode"`
	Realm    string `json:"realm"`
	Domain   string `json:"domain"`
	Hostname string `json:"hostname"`
	// VolumeWasEmpty records that the first boot started on empty volumes,
	// so a retry may wipe what it created.
	VolumeWasEmpty bool `json:"volume_was_empty"`
	// PrivateDir and SmbConf locate the domain (a restore keeps the
	// restored tree where samba-tool wrote it).
	PrivateDir string `json:"private_dir"`
	SmbConf    string `json:"smb_conf"`
	// Versions of the software that last ran the domain.
	SambaVersion     string    `json:"samba_version"`
	ImageVersion     string    `json:"image_version"`
	ConductorVersion string    `json:"conductor_version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	// RestoredFrom is the backup ID of a restore.
	RestoredFrom string `json:"restored_from,omitempty"`
}

// ErrNone means there is no state file.
var ErrNone = errors.New("state: no state file")

// Load reads the state file.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNone
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("state: %s: %w", path, err)
	}
	if s.Phase != PhaseFirstBoot && s.Phase != PhaseComplete {
		return nil, fmt.Errorf("state: %s: unknown phase %q", path, s.Phase)
	}
	return &s, nil
}

// Save writes the state file atomically (0600).
func Save(path string, s *State) error {
	s.UpdatedAt = time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = s.UpdatedAt
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
