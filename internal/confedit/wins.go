//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// Will the file we are about to write actually be read?
//
// sshd keeps the FIRST value it sees for a keyword, and reads sshd_config.d only where
// an Include line tells it to. So a drop-in takes effect when that Include comes before
// any line already setting the same thing — and does not when it comes after, or is
// missing.
//
// Measured on debian-13 (Include line 12, `X11Forwarding yes` line 92) and rocky-9
// (Include line 15): a 10- drop-in changed the effective value on both, so a live line
// further down the file is not an obstacle. Getting this backwards would mean writing a
// file, reporting success, and changing nothing — the worst possible outcome for a tool
// whose whole claim is that you can see what it did.

// DropInWins reports whether a drop-in for this setting would take effect, and says
// why not when it would not.
//
// mainConfig is the content of the service's main configuration file.
func DropInWins(s Setting, mainConfig string) (bool, string) {
	// apt.conf.d needs no Include: apt reads the whole directory, and the last file
	// wins. There is nothing to be shadowed by.
	if s.Style != StyleSSH {
		return true, ""
	}

	includeAt := includeLine(mainConfig)
	if includeAt == 0 {
		return false, fmt.Sprintf(
			"%s has no Include line for %s, so nothing placed there is read at all",
			filePath(s), sshDropInDir)
	}

	liveAt, liveText := firstLiveLine(s, mainConfig)
	if liveAt != 0 && liveAt < includeAt {
		return false, fmt.Sprintf(
			"%s already sets %s on line %d (%q), above the Include on line %d. "+
				"sshd keeps the first value it reads, so a file in %s would be read and ignored",
			filePath(s), s.Directive, liveAt, liveText, includeAt, sshDropInDir)
	}
	return true, ""
}

// includeLine returns the 1-based line number of the Include that reads the drop-in
// directory, or 0. A commented Include is not an Include.
func includeLine(content string) int {
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		first, rest, found := strings.Cut(trimmed, " ")
		if found && strings.EqualFold(first, "Include") && strings.Contains(rest, sshDropInDir) {
			return i + 1
		}
	}
	return 0
}

// firstLiveLine returns the 1-based line number and text of the first line that really
// sets this directive, or 0.
func firstLiveLine(s Setting, content string) (int, string) {
	for i, line := range strings.Split(content, "\n") {
		if isLiveDirective(s, line) {
			return i + 1, strings.TrimSpace(line)
		}
	}
	return 0, ""
}
