//go:build linux

package collect

import (
	"regexp"
	"strings"
)

var homePathPattern = regexp.MustCompile(`/home/[^/\s]+`)

// RedactCmdline removes home-directory path segments from a command line for ingest.
func RedactCmdline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return homePathPattern.ReplaceAllString(s, "[redacted]")
}
