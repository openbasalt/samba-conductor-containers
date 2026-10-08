package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if _, err := Load(p); !errors.Is(err, ErrNone) {
		t.Fatalf("missing file: %v", err)
	}
	s := &State{Phase: PhaseFirstBoot, Mode: "provision", Realm: "EXAMPLE.TEST", Hostname: "dc1", VolumeWasEmpty: true}
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	got, err := Load(p)
	if err != nil || got.Phase != PhaseFirstBoot || got.Realm != "EXAMPLE.TEST" || !got.VolumeWasEmpty || got.CreatedAt.IsZero() {
		t.Fatalf("%+v, %v", got, err)
	}
	if err := os.WriteFile(p, []byte(`{"phase":"weird"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unknown phase accepted")
	}
}
