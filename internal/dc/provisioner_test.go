package dc

import (
	"reflect"
	"strings"
	"testing"
)

func TestManagedOUs(t *testing.T) {
	base := "DC=example,DC=test"
	ous, chain, err := ManagedOUs(base, []string{"ou=Staff, OU=Lab,dc=Example,DC=test", "OU=Lab,DC=example,DC=test"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"OU=Staff,OU=Lab,DC=example,DC=test", "OU=Lab,DC=example,DC=test"}; !reflect.DeepEqual(ous, want) {
		t.Errorf("ous %q, want %q", ous, want)
	}
	// Top-down, each OU once.
	if want := []string{"OU=Lab,DC=example,DC=test", "OU=Staff,OU=Lab,DC=example,DC=test"}; !reflect.DeepEqual(chain, want) {
		t.Errorf("chain %q, want %q", chain, want)
	}
	for _, bad := range []string{
		"DC=example,DC=test", "CN=Users,DC=example,DC=test", "OU=People,DC=other,DC=test",
		"OU=Domain Controllers,DC=example,DC=test", "OU=x,OU=Domain Controllers,DC=example,DC=test",
		`OU=a\,b,DC=example,DC=test`, "OU=a(b),DC=example,DC=test", "OU=,DC=example,DC=test",
	} {
		if _, _, err := ManagedOUs(base, []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMissingEntries(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1200"
	have := "descriptor for OU=People,DC=example,DC=test:\nO:DAG:DAD:AI(A;;RPLCLORC;;;AU)" +
		"(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;" + sid + ")" +
		"(OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-9999)"
	got := MissingEntries(have, provisionerRights, sid)
	if len(got) != 3 {
		t.Fatalf("missing %q, want the three entries not held by %s", got, sid)
	}
	for _, e := range got {
		if !strings.HasPrefix(e, "(OA;CIIO;") || !strings.HasSuffix(e, ";bf967aba-0de6-11d0-a285-00aa003049e2;"+sid+")") {
			t.Errorf("entry %s", e)
		}
	}
	gf := MissingEntries("", googleFirstRights, sid)
	if len(gf) != 15 {
		t.Fatalf("%d Google-first entries, want 15", len(gf))
	}
	if gf[0] != "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;"+sid+")" ||
		gf[1] != "(OA;CIIO;SD;;bf967aba-0de6-11d0-a285-00aa003049e2;"+sid+")" {
		t.Errorf("create/delete entries %s %s", gf[0], gf[1])
	}
	if len(MissingEntries(strings.Join(MissingEntries("", provisionerRights, sid), ""), provisionerRights, sid)) != 0 {
		t.Error("entries already there reported missing")
	}
}
