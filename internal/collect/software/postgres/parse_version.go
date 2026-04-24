//go:build linux

package postgres

import "regexp"

var rePostgresVersion = regexp.MustCompile(`PostgreSQL\s+([\d.]+)`)

// parsePostgresVersion extracts the semver from "PostgreSQL 15.3 (Ubuntu 15.3-1.pgdg22.04+1)".
// Returns the clean version ("15.3") or the raw string if the pattern doesn't match.
func parsePostgresVersion(raw string) string {
	m := rePostgresVersion.FindStringSubmatch(raw)
	if len(m) >= 2 {
		return m[1]
	}
	return raw
}
