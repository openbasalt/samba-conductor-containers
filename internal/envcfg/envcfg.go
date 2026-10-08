// Package envcfg reads the SC_* configuration of the container entry points
// from the environment. Unknown SC_* variables are an error (a typo must
// fail loudly), and so is any variable that looks like it carries a secret:
// passwords and keys reach the containers only as files.
package envcfg

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Env is a snapshot of the environment (KEY=VALUE pairs), so tests need not
// touch the process environment.
type Env map[string]string

// FromOS returns the process environment.
func FromOS() Env { return FromList(os.Environ()) }

// FromList parses KEY=VALUE pairs.
func FromList(list []string) Env {
	e := Env{}
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			e[k] = v
		}
	}
	return e
}

// Get returns the value or def when the variable is unset or empty.
func (e Env) Get(key, def string) string {
	if v := strings.TrimSpace(e[key]); v != "" {
		return v
	}
	return def
}

// Bool reads a yes/no variable (1/0, on/off, true/false, yes/no).
func (e Env) Bool(key string, def bool) (bool, error) {
	v := strings.ToLower(e.Get(key, ""))
	switch v {
	case "":
		return def, nil
	case "1", "on", "true", "yes":
		return true, nil
	case "0", "off", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("%s=%q: expected on or off", key, e[key])
}

// secretLike reports whether a variable name looks like it holds a secret:
// *PASSWORD*, *PASS, *SECRET*, *_KEY, except *_FILE (a path to a file).
func secretLike(name string) bool {
	n := strings.ToUpper(name)
	if strings.HasSuffix(n, "_FILE") {
		return false
	}
	return strings.Contains(n, "PASSWORD") || strings.HasSuffix(n, "PASS") ||
		strings.Contains(n, "SECRET") || strings.HasSuffix(n, "_KEY")
}

// Check refuses unknown SC_* variables (allowed lists the known ones) and
// any variable whose name looks like a secret. hint names where secrets go.
func (e Env) Check(allowed []string, hint string) error {
	known := map[string]bool{}
	for _, a := range allowed {
		known[a] = true
	}
	var errs []string
	names := make([]string, 0, len(e))
	for k := range e {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if secretLike(k) && e[k] != "" {
			errs = append(errs, fmt.Sprintf("%s is set: secrets are never read from the environment; %s", k, hint))
			continue
		}
		if strings.HasPrefix(k, "SC_") && !known[k] {
			errs = append(errs, fmt.Sprintf("unknown variable %s (a typo?)", k))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// OneOf validates an enumerated value.
func (e Env) OneOf(key, def string, values ...string) (string, error) {
	v := strings.ToLower(e.Get(key, def))
	for _, ok := range values {
		if v == ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s=%q: expected one of %s", key, e[key], strings.Join(values, ", "))
}
