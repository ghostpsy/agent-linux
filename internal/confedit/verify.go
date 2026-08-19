//go:build linux

package confedit

import (
	"strings"
)

// sameMeaning lists values a service may report back under a different name.
//
// OpenSSH takes `prohibit-password` and prints `without-password`: the second is
// the older name for the same thing, and which one `sshd -T` shows depends on the
// build. Comparing the text alone therefore reported a correct server as wrong,
// and rolled back a change that had worked — found on a real machine, on the
// first end-to-end run.
//
// This is a synonym table, not a leniency table. It maps one value to other
// spellings of that *same* value, and never to a weaker one: `no` is stricter
// than `without-password`, so those two are not in here together.
var sameMeaning = map[string][]string{
	"prohibit-password": {"without-password"},
	"without-password":  {"prohibit-password"},
}

// matchesEffective reports whether the running service has this setting.
func matchesEffective(s Setting, value, effective string) bool {
	wanted := append([]string{value}, sameMeaning[value]...)

	for _, line := range strings.Split(effective, "\n") {
		if !isLiveDirective(s, line) {
			continue
		}
		current := directiveValue(s, line)
		for _, candidate := range wanted {
			if strings.EqualFold(current, candidate) {
				return true
			}
		}
	}
	return false
}

// Effective reports what the service says it is running with, and whether that is the
// value that was asked for.
//
// It takes the text rather than running the command. Verify used to shell out to
// `sshd -T` from here, which meant a privileged command that appeared in no registry
// and in no grant file — nobody reading /etc/sudoers.d/ghostpsy would know it ran. Now
// the command is declared, the caller runs it through privexec, and the judgement
// happens on the output.
func Effective(s Setting, value, reported string) (string, bool) {
	if matchesEffective(s, value, reported) {
		return value, true
	}
	return reportedValue(s, reported), false
}

// reportedValue is the value the service printed for this directive.
func reportedValue(s Setting, reported string) string {
	for _, line := range strings.Split(reported, "\n") {
		if isLiveDirective(s, line) {
			return directiveValue(s, line)
		}
	}
	return "nothing at all"
}
