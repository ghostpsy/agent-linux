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

// The preview a person approves has to contain both, or they are approving a
// sentence rather than a change.
func TestThePreviewCarriesTheDiffAndTheRecipe(t *testing.T) {
	s := withEtc(t, "Port 22\nPermitRootLogin yes\n")

	out, err := Preview(s, "prohibit-password")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"-PermitRootLogin yes",
		"+PermitRootLogin prohibit-password",
		"same change by hand",
		"sed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the preview is missing %q:\n%s", want, out)
		}
	}
	// And it must not pretend we ran shell.
	if !strings.Contains(out, "ghostpsy makes this change itself") {
		t.Errorf("the preview has to say we did not shell out:\n%s", out)
	}
}

func TestApplyReportsWhatItActuallyChanged(t *testing.T) {
	s := withEtc(t, "Port 22\nPermitRootLogin yes\n")

	out, err := Apply(s, "prohibit-password")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "-PermitRootLogin yes") || !strings.Contains(out, "+PermitRootLogin prohibit-password") {
		t.Errorf("the result has to show the change that was made:\n%s", out)
	}
}

// Everything ghostpsy does has to be on screen as something ghostpsy does.
//
// The copy-aside was only in the by-hand recipe, under a heading saying we do not run
// those commands — so the one step that makes the change reversible looked
// hypothetical. It is not: we take that copy, every time, before touching anything. A
// person reading the report has to be able to see every operation we perform, or "you
// can see exactly what we do" is not true.
func TestThePreviewListsEveryOperationGhostpsyPerforms(t *testing.T) {
	s := withEtc(t, "Port 22\nPermitRootLogin yes\n")

	out, err := Preview(s, "prohibit-password")
	if err != nil {
		t.Fatal(err)
	}

	steps := stepsSection(out)
	if !strings.Contains(steps, "copy") || !strings.Contains(steps, BackupSuffix) {
		t.Errorf("the copy we take is an operation we perform, so it has to be listed:\n%s", out)
	}
	if !strings.Contains(steps, "replace") {
		t.Errorf("writing the file is an operation we perform, so it has to be listed:\n%s", out)
	}
	// Numbered, because the order is the safety: the copy exists before the write.
	if !strings.Contains(steps, "1.") || !strings.Contains(steps, "2.") {
		t.Errorf("the order matters and has to be visible:\n%s", out)
	}
}

func TestApplyAlsoListsEveryOperationItPerformed(t *testing.T) {
	s := withEtc(t, "Port 22\nPermitRootLogin yes\n")

	out, err := Apply(s, "prohibit-password")
	if err != nil {
		t.Fatal(err)
	}

	steps := stepsSection(out)
	if !strings.Contains(steps, BackupSuffix) {
		t.Errorf("the copy it took has to be reported:\n%s", out)
	}
	if !strings.Contains(steps, "replace") {
		t.Errorf("the write it did has to be reported:\n%s", out)
	}
}

// The undo performs operations too, and they were reported as one sentence.
func TestRestoreListsWhatItPutBack(t *testing.T) {
	s := withEtc(t, "Port 22\nPermitRootLogin yes\n")
	if _, err := Apply(s, "prohibit-password"); err != nil {
		t.Fatal(err)
	}

	out, err := Restore(s)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, BackupSuffix) {
		t.Errorf("the undo has to name the copy it put back:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "removed") {
		t.Errorf("it also deletes the copy, so it has to say so:\n%s", out)
	}
}

// stepsSection is the part of the output listing what ghostpsy itself does, as
// opposed to the by-hand recipe below it.
func stepsSection(out string) string {
	_, rest, found := strings.Cut(out, "ghostpsy does this itself")
	if !found {
		return ""
	}
	steps, _, _ := strings.Cut(rest, "The same")
	return steps
}
