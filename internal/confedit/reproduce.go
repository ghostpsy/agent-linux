//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// How a person checks what we did, and does it themselves if they want to.
//
// The output used to be the command we invoked — `ghostpsy write-config --mode=apply
// --key=… --value=…` — which tells a sysadmin nothing at all. They cannot see what
// changed, cannot reproduce it, and cannot verify it afterwards. That is exactly the
// opacity this design exists to avoid, sitting in the middle of it.
//
// Two things fix that, and both are needed:
//
//	the diff      what actually changed, so it can be checked
//	the recipe    the same change as ordinary commands, so it can be repeated
//
// What is deliberately *not* claimed is that we ran those commands. We do not: the
// file is written atomically in Go, so that only the settings on the declared list
// can be reached and a half-written sshd_config is impossible. Printing a sed line as
// "what ran" would be a lie in the other direction, so the recipe says what it is.

// diffContext is how many unchanged lines to show either side of a change. Two is
// enough to find the place in the file without printing the file.
const diffContext = 2

// unifiedDiff shows what changed between two versions of a file.
//
// Deliberately simple, because the change is always simple: this package replaces one
// line or appends a few. Anything more elaborate would be machinery for a case that
// cannot arise.
func unifiedDiff(path, before, after string) string {
	if before == after {
		return ""
	}

	oldLines := strings.Split(strings.TrimRight(before, "\n"), "\n")
	newLines := strings.Split(strings.TrimRight(after, "\n"), "\n")
	first, lastOld, lastNew := changedRange(oldLines, newLines)

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s   (after this change)\n", path, path)

	for i := max(0, first-diffContext); i < first; i++ {
		fmt.Fprintf(&b, " %s\n", oldLines[i])
	}
	for i := first; i <= lastOld && i < len(oldLines); i++ {
		fmt.Fprintf(&b, "-%s\n", oldLines[i])
	}
	for i := first; i <= lastNew && i < len(newLines); i++ {
		fmt.Fprintf(&b, "+%s\n", newLines[i])
	}
	for i := lastOld + 1; i < len(oldLines) && i <= lastOld+diffContext; i++ {
		fmt.Fprintf(&b, " %s\n", oldLines[i])
	}
	return b.String()
}

// changedRange finds the first line that differs and the last on each side.
//
// Walking in from both ends keeps the unchanged parts of the file out of the diff,
// which is the whole point: a person checking one setting should not have to read a
// hundred lines they did not ask about.
func changedRange(oldLines, newLines []string) (first, lastOld, lastNew int) {
	first = 0
	for first < len(oldLines) && first < len(newLines) && oldLines[first] == newLines[first] {
		first++
	}

	endOld, endNew := len(oldLines)-1, len(newLines)-1
	for endOld >= first && endNew >= first && oldLines[endOld] == newLines[endNew] {
		endOld--
		endNew--
	}
	return first, endOld, endNew
}

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
		out = append(out, "sudo "+c)
	}
	return out
}
