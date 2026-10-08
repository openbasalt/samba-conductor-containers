package envcfg

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	allowed := []string{"SC_MODE", "SC_REALM"}
	ok := FromList([]string{"SC_MODE=run", "PATH=/usr/bin", "HOME=/", "KRB5_CONFIG=/x", "CREDENTIALS_DIRECTORY=/run/c", "SC_PASSWORD_FILE=/run/secrets/x"})
	// SC_PASSWORD_FILE is a path (allowed by the secret rule) but unknown.
	if err := ok.Check(append(allowed, "SC_PASSWORD_FILE"), "hint"); err != nil {
		t.Fatalf("clean environment refused: %v", err)
	}
	for _, bad := range []string{"SC_MODEE=run", "ADMIN_PASSWORD=x", "SC_ADMIN_PASS=x", "DB_SECRET_X=y", "SIGNING_KEY=z"} {
		err := FromList([]string{bad}).Check(allowed, "use files")
		if err == nil {
			t.Errorf("%s accepted", bad)
			continue
		}
		name, _, _ := strings.Cut(bad, "=")
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error does not name the variable: %v", bad, err)
		}
	}
	// An empty secret-looking variable is harmless.
	if err := FromList([]string{"SOME_PASSWORD="}).Check(allowed, ""); err != nil {
		t.Errorf("empty variable refused: %v", err)
	}
}

func TestBoolAndOneOf(t *testing.T) {
	e := FromList([]string{"A=on", "B=0", "C=maybe", "M=Host"})
	if v, err := e.Bool("A", false); err != nil || !v {
		t.Error("A")
	}
	if v, err := e.Bool("B", true); err != nil || v {
		t.Error("B")
	}
	if _, err := e.Bool("C", false); err == nil {
		t.Error("C accepted")
	}
	if v, err := e.Bool("UNSET", true); err != nil || !v {
		t.Error("default")
	}
	if v, err := e.OneOf("M", "bridge", "bridge", "host"); err != nil || v != "host" {
		t.Errorf("OneOf = %q, %v", v, err)
	}
	if _, err := e.OneOf("C", "x", "x", "y"); err == nil {
		t.Error("OneOf accepted an unknown value")
	}
}
