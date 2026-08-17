//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// Set returns the file with one setting changed, and whether anything changed.
//
// It is a pure function on purpose. Everything that could go wrong with editing
// somebody's sshd_config — replacing the wrong line, leaving two answers to one
// question, editing a comment that has no effect — is decided here, where it can
// be tested against real files without touching one.
func Set(s Setting, content, value string) (string, bool) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		if !isLiveDirective(s, line) {
			continue
		}
		replacement := directiveLine(s, value)
		if line == replacement {
			// Already right. Rewriting it would take a backup and claim a change
			// that did not happen.
			return content, false
		}
		lines[i] = replacement
		// The first occurrence only. sshd uses the first value for a keyword and
		// ignores every later one, so editing a later line would look correct in
		// the file and change nothing on the server.
		return strings.Join(lines, "\n"), true
	}

	return appendDirective(content, directiveLine(s, value)), true
}

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

// appendDirective adds the line at the end, with a note saying who wrote it.
//
// The note matters more than it looks: the person who finds this line in six
// months needs to know a tool put it there, and which one.
func appendDirective(content, line string) string {
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "\n# set by ghostpsy\n" + line + "\n"
}
