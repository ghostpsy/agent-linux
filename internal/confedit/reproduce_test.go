//go:build linux

package confedit

import (
	"strings"
	"testing"
)

// A refusal nobody can act on is a refusal that gets worked around.
//
// These commands are handed over when ghostpsy will not make the change itself. They
// are pasted into a root shell by a person, so they have to be right and runnable as
// they stand: a recipe that fails on its first line is worse than no recipe.

// The recipe for a setting that is not in the file yet is exactly what we do:
// append it, with the note saying who put it there.
func TestTheRecipeForAnAbsentSettingIsExactlyWhatWeDo(t *testing.T) {
	commands := equivalentCommands(sshSetting(t), "prohibit-password", "Port 22\n")

	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, ">> /etc/ssh/sshd_config") {
		t.Errorf("an absent setting is appended, got:\n%s", joined)
	}
	if !strings.Contains(joined, "set by ghostpsy") {
		t.Errorf("the note we write has to be in the recipe too, got:\n%s", joined)
	}
	// And the copy comes first, because that is the order we do it in.
	if !strings.HasPrefix(joined, "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.ghostpsy-backup") {
		t.Errorf("the backup has to come first, got:\n%s", joined)
	}
}

// The recipe for a setting that is already there has to change the first live line
// and leave a commented default alone — because that is what we do, and a recipe
// that does something else is not a recipe for this change.
func TestTheRecipeForAnExistingSettingChangesOnlyTheFirstLiveLine(t *testing.T) {
	before := "#PermitRootLogin no\nPermitRootLogin yes\nPermitRootLogin yes\n"

	commands := equivalentCommands(sshSetting(t), "prohibit-password", before)
	joined := strings.Join(commands, "\n")

	if !strings.Contains(joined, "sed") {
		t.Errorf("an existing line is edited in place, got:\n%s", joined)
	}
	// `0,/re/` is the address form that stops at the first match. Without it sed
	// would rewrite every occurrence and uncomment the commented default, which is
	// not the change ghostpsy made.
	if !strings.Contains(joined, "0,/") {
		t.Errorf("the recipe must stop at the first match, got:\n%s", joined)
	}
}

func TestTheAptRecipeUsesTheAptForm(t *testing.T) {
	commands := equivalentCommands(aptSetting(t), "1", "")

	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, `APT::Periodic::Unattended-Upgrade "1";`) {
		t.Errorf("expected the apt form with quotes and a semicolon, got:\n%s", joined)
	}
}

// The recipe is now advice for a change ghostpsy refuses, so it has to be runnable as
// it stands — which means every line carries sudo. A pasted recipe that fails on the
// first line is worse than no recipe.
func TestByHandCommandsCanBePastedAsTheyAre(t *testing.T) {
	s, _ := Lookup("ssh.max_auth_tries")
	commands := ByHandCommands(s, "5", "MaxAuthTries 10\n")
	if len(commands) == 0 {
		t.Fatal("no commands to give")
	}
	for _, c := range commands {
		if !strings.HasPrefix(c, "sudo ") {
			t.Errorf("this line would fail as a normal user: %q", c)
		}
	}
	joined := strings.Join(commands, "\n")
	// The copy aside, the edit, and the check that makes it safe.
	for _, want := range []string{".ghostpsy-backup", "MaxAuthTries 5", "sshd -t"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the recipe is missing %q:\n%s", want, joined)
		}
	}
}

// sudo has to be on every command, not on every line.
//
// One line is `systemctl reload sshd || systemctl reload ssh` — the two names Debian
// and RHEL use for the same service. Prefixing the line gave
// `sudo systemctl reload sshd || systemctl reload ssh`, so the fallback half ran
// unprivileged and failed with "Access denied" for the person who pasted it. It failed
// on exactly the path that exists because the first name can be the wrong one.
func TestEveryCommandInTheAdviceRunsAsRoot(t *testing.T) {
	for _, line := range ByHandCommands(sshSetting(t), "prohibit-password", "PermitRootLogin yes\n") {
		for _, command := range strings.Split(line, "||") {
			if !strings.HasPrefix(strings.TrimSpace(command), "sudo ") {
				t.Errorf("this command is not run as root:\n\t%s\nin the line:\n\t%s", command, line)
			}
		}
	}
}
