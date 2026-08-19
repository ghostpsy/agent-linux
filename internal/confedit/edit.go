//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// Value reads what the setting is currently set to, ignoring comments.
func Value(s Setting, content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		if !isLiveDirective(s, line) {
			continue
		}
		return directiveValue(s, line), true
	}
	return "", false
}

// isLiveDirective reports whether a line sets this directive and is not a
// comment. A commented default is left exactly where it is: it is the record of
// what the machine used to think, and removing it helps nobody.
func isLiveDirective(s Setting, line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return false
	}

	switch s.Style {
	case StyleSSH:
		// sshd treats keywords as case-insensitive, so a file written as
		// `permitrootlogin yes` is a real setting and has to be found.
		first, _, _ := strings.Cut(trimmed, " ")
		return strings.EqualFold(first, s.Directive)
	case StyleAPTConf:
		return strings.HasPrefix(trimmed, s.Directive+" ") ||
			strings.HasPrefix(trimmed, s.Directive+"\t")
	}
	return false
}

func directiveValue(s Setting, line string) string {
	trimmed := strings.TrimSpace(line)
	_, rest, _ := strings.Cut(trimmed, " ")
	rest = strings.TrimSpace(rest)

	if s.Style == StyleAPTConf {
		rest = strings.TrimSuffix(rest, ";")
		rest = strings.Trim(rest, `"`)
	}
	return strings.TrimSpace(rest)
}

func directiveLine(s Setting, value string) string {
	if s.Style == StyleAPTConf {
		return fmt.Sprintf("%s %q;", s.Directive, value)
	}
	return s.Directive + " " + value
}
