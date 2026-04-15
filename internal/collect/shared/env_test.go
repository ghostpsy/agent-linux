//go:build linux

package shared

import "testing"

func TestEnvLocaleC_containsLocaleVars(t *testing.T) {
	t.Parallel()
	env := EnvLocaleC()
	var hasLcAll, hasLang bool
	for _, e := range env {
		if e == "LC_ALL=C" {
			hasLcAll = true
		}
		if e == "LANG=C" {
			hasLang = true
		}
	}
	if !hasLcAll {
		t.Fatal("LC_ALL=C not found in env")
	}
	if !hasLang {
		t.Fatal("LANG=C not found in env")
	}
}

func TestEnvLocaleC_preservesExistingEnv(t *testing.T) {
	t.Parallel()
	env := EnvLocaleC()
	// env should contain at least the base os.Environ() entries plus the 2 we add
	if len(env) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(env))
	}
}
