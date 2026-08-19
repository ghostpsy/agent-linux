//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// How somebody makes a change ghostpsy refuses to make.
//
// There is one such change: the main configuration file already sets the directive
// above its Include line, so no drop-in can ever be read, and editing a line this
// server's owner wrote is not something ghostpsy does. Refusing and stopping there
// would send them to do it from memory at midnight, so the refusal carries the
// commands instead.
//
// Everything here is advice. ghostpsy runs none of it — it installs its own file, and
// that is the only way it changes a setting.

// equivalentCommands is the same change, written as ordinary system commands.
//
// It is chosen by what the file actually contains, because the two cases are
// genuinely different work: a setting already there is edited in place, and one that
// is absent is appended with the note saying who put it there.
func equivalentCommands(s Setting, value, content string) []string {
	path := filePath(s)
	line := directiveLine(s, value)

	commands := []string{
		fmt.Sprintf("cp %s %s%s", path, path, BackupSuffix),
	}

	if _, present := Value(s, content); !present {
		// Exactly what appendDirective does, including the note.
		commands = append(commands,
			fmt.Sprintf("printf '\\n# set by ghostpsy\\n%%s\\n' %s >> %s", quote(line), path))
		return append(commands, checkCommands(s)...)
	}

	// `0,/re/` stops at the first match, which is the only line sshd reads and the
	// only one this package changes. Without it sed would rewrite every occurrence
	// and uncomment the commented default — a different change from the one made.
	// GNU sed, which is every Linux this agent supports.
	commands = append(commands, fmt.Sprintf(
		"sed -i '0,/%s/s|%s|%s|' %s",
		matchPrefix(s), matchLine(s), line, path))
	return append(commands, checkCommands(s)...)
}

// checkCommands are the steps that make the change safe, in the order we do them.
//
// They belong in the recipe: somebody copying the edit without the check is copying
// the dangerous half. This is the same order the action itself uses.
func checkCommands(s Setting) []string {
	switch s.Style {
	case StyleSSH:
		return []string{
			"sshd -t                    # stop here if this fails",
			"systemctl reload sshd || systemctl reload ssh",
			fmt.Sprintf("sshd -T | grep -i %s   # what sshd now believes", strings.ToLower(s.Directive)),
		}
	case StyleAPTConf:
		return []string{
			fmt.Sprintf("apt-config dump | grep %s", s.Directive),
		}
	}
	return nil
}

// matchPrefix and matchLine are the patterns the recipe uses to find the line.
//
// Anchored to the start, so a directive mentioned inside a comment further down the
// file is not what gets edited.
func matchPrefix(s Setting) string {
	if s.Style == StyleAPTConf {
		return "^" + escapeForSed(s.Directive)
	}
	return "^" + s.Directive
}

func matchLine(s Setting) string {
	return matchPrefix(s) + ".*"
}

// escapeForSed protects the characters a directive can contain that sed would read
// as syntax. Only the apt names have any: APT::Periodic::… has no metacharacters,
// but a future one might.
func escapeForSed(text string) string {
	for _, ch := range []string{"\\", ".", "*", "[", "]", "^", "$", "|"} {
		text = strings.ReplaceAll(text, ch, "\\"+ch)
	}
	return text
}

// quote wraps a value for a shell, the safe way round: single quotes, with any
// single quote in the value closed and reopened. Values here are narrow enough that
// this cannot trigger, and relying on that rather than doing it properly is how a
// quoting bug gets shipped.
func quote(text string) string {
	return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'"
}

// ByHandCommands is the change written out for somebody to run themselves.
//
// It was built to sit beside a change ghostpsy had just made, labelled "the same
// thing by hand". That reading is gone: ghostpsy now writes a file of its own rather
// than editing one somebody else owns, so there is nothing to be the equivalent of.
//
// What is left is the case we refuse — a main configuration file that already sets
// this directive above its Include line, where a drop-in would be read and ignored.
// ghostpsy will not edit a line it did not write, so these commands are the answer to
// "then how do I do it", and they are the same shape as the advice a dangerous change
// carries: the risk, the check, and something to paste.
func ByHandCommands(s Setting, value, content string) []string {
	commands := equivalentCommands(s, value, content)
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, asRoot(c))
	}
	return out
}

// asRoot puts sudo on every command in a line, not only on the first.
//
// One line is `systemctl reload sshd || systemctl reload ssh`, the two names Debian and
// RHEL use for the same service. Prefixing the line left the fallback half
// unprivileged, so it failed for the person pasting it — on exactly the path that
// exists because the first name can be the wrong one.
func asRoot(line string) string {
	commands := strings.Split(line, "||")
	for i, command := range commands {
		commands[i] = "sudo " + strings.TrimSpace(command)
	}
	return strings.Join(commands, " || ")
}
