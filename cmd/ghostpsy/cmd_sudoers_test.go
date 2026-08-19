//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A host with none of the declared software needs no privilege at all. Saying
// that plainly matters: a file with a header and no rules looks like something
// went wrong, and the user cannot tell an empty grant from a broken generator.
func TestSudoersCommandSaysSoWhenNothingNeedsGranting(t *testing.T) {
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sudoers command failed: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "NOPASSWD:") {
		t.Skip("this host has some of the declared software installed; nothing to assert")
	}
	if !strings.Contains(got, "nothing on this server needs") {
		t.Fatalf("expected a plain explanation that no privilege is needed, got:\n%s", got)
	}
}

// The file has to say where it came from and how to install it, because the
// person reading it did not generate it and needs to know it is ours.
func TestSudoersCommandExplainsWhereTheFileGoes(t *testing.T) {
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sudoers command failed: %v", err)
	}

	got := out.String()
	for _, want := range []string{"/etc/sudoers.d/ghostpsy", "visudo"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the header to mention %q, got:\n%s", want, got)
		}
	}
}

// After an upgrade the agent may need a command the installed rule does not
// grant. Silence there is the dangerous case: collectors would start failing
// for a reason nobody connects to the upgrade.
func TestSudoersCheckReportsDriftAgainstTheInstalledFile(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "ghostpsy")
	if err := os.WriteFile(stale, []byte("# an old grant that no longer matches\n"), 0o440); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	drifted, err := sudoersHasDriftedWith(stale, os.ReadFile)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !drifted {
		t.Fatal("expected a stale grant file to be reported as drifted")
	}
}

func TestSudoersCheckIsQuietWhenTheInstalledFileMatches(t *testing.T) {
	current := filepath.Join(t.TempDir(), "ghostpsy")
	if err := os.WriteFile(current, []byte(sudoersFile()), 0o440); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	drifted, err := sudoersHasDriftedWith(current, os.ReadFile)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drifted {
		t.Fatal("expected an up-to-date grant file to report no drift")
	}
}

// A missing file is not drift, it is "never installed". The two need different
// advice, so they must not collapse into one answer.
func TestSudoersCheckSaysWhenNoGrantIsInstalledAtAll(t *testing.T) {
	_, err := sudoersHasDrifted(filepath.Join(t.TempDir(), "absent"))

	if !errors.Is(err, errNoGrantInstalled) {
		t.Fatalf("expected errNoGrantInstalled, got: %v", err)
	}
}

func TestSudoersCheckTellsTheUserWhatToDoWhenNothingIsInstalled(t *testing.T) {
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--check", "--path", filepath.Join(t.TempDir(), "absent")})

	err := cmd.Execute()

	if err == nil {
		t.Fatal("expected a missing grant to be reported as an error")
	}
	got := out.String() + err.Error()
	if !strings.Contains(got, "ghostpsy sudoers") {
		t.Fatalf("expected the message to say how to fix it, got:\n%s", got)
	}
}

func TestSudoersDiffShowsWhatAnUpgradeWouldChange(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "ghostpsy")
	if err := os.WriteFile(stale, []byte("# stale line that is not in the current grant\n"), 0o440); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--diff", "--path", stale})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("diff failed: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "- # stale line that is not in the current grant") {
		t.Fatalf("expected the removed line to be shown, got:\n%s", got)
	}
}

// --check reads the installed grant through the privileged reader, because the agent
// user cannot open a 0440 root:root file. --diff opened it directly, so the very advice
// --check prints — "See what changed with: ghostpsy sudoers --diff" — answered
// "permission denied" for the only user that ever runs the check.
//
// Measured on debian-13, as the ghostpsy user, with the real grant installed.
func TestSudoersDiffReadsTheInstalledGrantTheSameWayTheCheckDoes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ghostpsy")
	if err := os.WriteFile(path, []byte("# what only root can read\n"), 0o440); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	err := runSudoersDiffWith(&out, path, func(string) ([]byte, error) {
		return []byte("# what the privileged reader returned\n"), nil
	})

	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "- # what the privileged reader returned") {
		t.Fatalf("the diff has to compare against what the reader returned, got:\n%s", got)
	}
	if strings.Contains(got, "what only root can read") {
		t.Fatalf("the diff opened the file itself, which the agent user cannot do:\n%s", got)
	}
}
