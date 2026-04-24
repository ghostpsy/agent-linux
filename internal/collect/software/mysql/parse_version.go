//go:build linux

package mysql

import "regexp"

var reMysqlVersion = regexp.MustCompile(`([\d]+\.[\d]+\.[\d]+)`)

// parseMysqlVersion extracts the semver from "mysqld Ver 8.0.35-0ubuntu0.22.04.1 for Linux...".
// Returns the clean version ("8.0.35") or the raw string if the pattern doesn't match.
func parseMysqlVersion(raw string) string {
	m := reMysqlVersion.FindStringSubmatch(raw)
	if len(m) >= 2 {
		return m[1]
	}
	return raw
}
