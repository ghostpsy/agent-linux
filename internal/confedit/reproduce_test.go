//go:build linux

package confedit

import (
	"strings"
	"testing"
)

// A change nobody can check is a change nobody should trust.
//
// The output used to be `sudo ghostpsy write-config --mode=apply --key=… --value=…`,
// which tells a sysadmin nothing. They cannot see what it did, cannot reproduce it,
// and cannot verify it afterwards. That is the opacity this whole design exists to
// avoid, and it was sitting in the middle of it.
//
// Two things answer that, and both are needed. A diff says what actually changed. A
// by-hand recipe says how to do the same thing without us. Neither claims we ran
// shell — we do not, and saying we did would be a different lie.

func TestTheDiffShowsExactlyWhichLineChanged(t *testing.T) {
	before := "Port 22\n#PermitRootLogin prohibit-password\nX11Forwarding yes\n"
	after, _ := Set(sshSetting(t), before, "prohibit-password")

	diff := unifiedDiff("/etc/ssh/sshd_config", before, after)

	if !strings.Contains(diff, "+PermitRootLogin prohibit-password") {
		t.Errorf("the added line has to be visible, got:\n%s", diff)
	}
	if !strings.Contains(diff, "/etc/ssh/sshd_config") {
		t.Errorf("the diff has to name the file, got:\n%s", diff)
	}
	// A line nobody touched must not appear as a change.
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "-") && strings.Contains(line, "Port 22") {
			t.Errorf("an untouched line was reported as removed:\n%s", diff)
		}
	}
}

func TestTheDiffOfAReplacedLineShowsBothSides(t *testing.T) {
	before := "PermitRootLogin yes\n"
	after, _ := Set(sshSetting(t), before, "prohibit-password")

	diff := unifiedDiff("/etc/ssh/sshd_config", before, after)

	if !strings.Contains(diff, "-PermitRootLogin yes") {
		t.Errorf("the old line has to be shown, got:\n%s", diff)
	}
	if !strings.Contains(diff, "+PermitRootLogin prohibit-password") {
		t.Errorf("the new line has to be shown, got:\n%s", diff)
	}
}

func TestNoDiffWhenNothingChanges(t *testing.T) {
	same := "PermitRootLogin prohibit-password\n"

	if diff := unifiedDiff("/etc/ssh/sshd_config", same, same); diff != "" {
		t.Errorf("expected no diff at all, got:\n%s", diff)
	}
}

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
