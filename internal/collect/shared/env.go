//go:build linux

package shared

import "os"

// EnvLocaleC forces C locale for deterministic CLI output parsing.
func EnvLocaleC() []string {
	base := os.Environ()
	base = append(base, "LC_ALL=C")
	base = append(base, "LANG=C")
	return base
}
