package setup

import (
	"strings"
	"testing"
)

func TestTomlSection(t *testing.T) {
	in := "[server]\nlisten = \":8443\"\n\n[webauthn]\n# comment\nrp_id = \"conductor.example.test\"\nadmin_required = false\n\n[bulk]\nmax_rows = 1000\n"
	out := tomlSection(in, "webauthn", [][2]string{{"rp_id", `"example.test"`}, {"origins", `["https://a", "https://b"]`}})
	for _, want := range []string{"rp_id = \"example.test\"\n", "origins = [\"https://a\", \"https://b\"]\n", "admin_required = false\n", "[bulk]\nmax_rows = 1000\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "conductor.example.test") {
		t.Errorf("old rp_id kept:\n%s", out)
	}
	if strings.Index(out, "origins") > strings.Index(out, "[bulk]") {
		t.Errorf("origins outside [webauthn]:\n%s", out)
	}
	out2 := tomlSection(out, "sync", [][2]string{{"enabled", "true"}})
	if !strings.HasSuffix(out2, "\n[sync]\nenabled = true\n") {
		t.Errorf("new section:\n%s", out2)
	}
	if tomlSection(out2, "sync", [][2]string{{"enabled", "true"}}) != out2 {
		t.Error("not idempotent")
	}
}

func TestBaseDN(t *testing.T) {
	if got := baseDN("AD.EXAMPLE.TEST"); got != "DC=ad,DC=example,DC=test" {
		t.Fatal(got)
	}
}
