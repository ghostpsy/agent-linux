//go:build linux

package core

import (
	"os"
	"strings"
)

// osRelease holds fields read from /etc/os-release (sent raw to the API for EOL derivation).
type osRelease struct {
	ID         string
	Name       string
	Version    string // VERSION= e.g. 12 (bookworm)
	VersionID  string
	PrettyName string
}

func parseOSRelease() osRelease {
	var r osRelease
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return r
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "ID="):
			r.ID = unquoteOSReleaseValue(strings.TrimPrefix(line, "ID="))
		case strings.HasPrefix(line, "NAME="):
			r.Name = unquoteOSReleaseValue(strings.TrimPrefix(line, "NAME="))
		case strings.HasPrefix(line, "VERSION_ID="):
			r.VersionID = unquoteOSReleaseValue(strings.TrimPrefix(line, "VERSION_ID="))
		case strings.HasPrefix(line, "VERSION="):
			r.Version = unquoteOSReleaseValue(strings.TrimPrefix(line, "VERSION="))
		case strings.HasPrefix(line, "PRETTY_NAME="):
			r.PrettyName = unquoteOSReleaseValue(strings.TrimPrefix(line, "PRETTY_NAME="))
		}
	}
	return r
}

func unquoteOSReleaseValue(s string) string {
	s = strings.TrimSpace(s)
	return strings.Trim(s, `"`)
}
