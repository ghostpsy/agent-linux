//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSetup struct {
	ran         []string
	visudoFails bool
}

func (f *fakeSetup) run(name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.ran = append(f.ran, call)
	if f.visudoFails && strings.Contains(call, "visudo") {
		return errors.New("parse error near line 3")
	}
	return nil
}

func (f *fakeSetup) did(s string) bool {
	for _, c := range f.ran {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

// The single most dangerous step in the whole install. A malformed file in
// /etc/sudoers.d can lock every administrator out of sudo on the host, so the
// system's own checker runs against a temporary copy first.
func TestSudoRuleIsCheckedByVisudoBeforeItIsInstalled(t *testing.T) {
	f := &fakeSetup{}
	dest := filepath.Join(t.TempDir(), "ghostpsy")

	if err := installSudoRule(dest, "rule\n", f.run); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	if !f.did("visudo -c -f") {
		t.Fatalf("visudo was never run, calls: %v", f.ran)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("the rule was not installed: %v", err)
	}
}

// If the check fails we stop and change nothing. The user's sudo setup must be
// exactly as we found it.
func TestABadSudoRuleIsNeverInstalled(t *testing.T) {
	f := &fakeSetup{visudoFails: true}
	dest := filepath.Join(t.TempDir(), "ghostpsy")

	err := installSudoRule(dest, "this is not valid sudoers\n", f.run)

	if err == nil {
		t.Fatal("expected the install to be refused")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("a rule that failed the check was installed anyway")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("the message should tell the user their sudo setup is untouched, got: %v", err)
	}
}

// Old sudo ignores /etc/sudoers.d entirely unless #includedir is present. A
// grant that looks applied but is never read is worse than no grant, because
// nothing reports it.
func TestSetupRefusesWhenSudoersDoesNotIncludeTheDirectory(t *testing.T) {
	sudoers := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoers, []byte("Defaults env_reset\nroot ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	err := checkSudoersIncludesDropInDir(sudoers)

	if err == nil {
		t.Fatal("expected setup to refuse when #includedir is missing")
	}
	if !strings.Contains(err.Error(), "includedir") {
		t.Errorf("the message should name what is missing, got: %v", err)
	}
}

func TestSetupAcceptsSudoersWithTheIncludeDirective(t *testing.T) {
	sudoers := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoers, []byte("Defaults env_reset\n#includedir /etc/sudoers.d\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	if err := checkSudoersIncludesDropInDir(sudoers); err != nil {
		t.Fatalf("a sudoers file with #includedir must be accepted, got: %v", err)
	}
}

// sudo is the mechanism the whole privilege model stands on. If it is missing
// we install it, because almost every host that lacks it has a working package
// manager — and if that fails we stop rather than fall back to root.
func TestEnsureSudoInstallsItWhenMissing(t *testing.T) {
	f := &fakeSetup{}

	err := ensureSudo(func() bool { return false }, "apt-get", f.run)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.did("apt-get") || !f.did("sudo") {
		t.Fatalf("expected sudo to be installed with apt-get, calls: %v", f.ran)
	}
}

func TestEnsureSudoDoesNothingWhenItIsAlreadyThere(t *testing.T) {
	f := &fakeSetup{}

	if err := ensureSudo(func() bool { return true }, "apt-get", f.run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(f.ran) != 0 {
		t.Fatalf("nothing should have been installed, calls: %v", f.ran)
	}
}

// The honest dead end. There is no root mode, so if sudo cannot be installed
// the message has to say plainly what happened and what to do.
func TestEnsureSudoStopsClearlyWhenItCannotBeInstalled(t *testing.T) {
	failing := func(string, ...string) error { return errors.New("Cannot find a valid baseurl for repo") }

	err := ensureSudo(func() bool { return false }, "yum", failing)

	if err == nil {
		t.Fatal("expected setup to stop")
	}
	for _, want := range []string{"sudo", "install"} {
		if !strings.Contains(strings.ToLower(err.Error()), want) {
			t.Errorf("the message should mention %q, got: %v", want, err)
		}
	}
}

// A host with no known package manager cannot be helped automatically, and
// guessing a command would be worse than saying so.
func TestEnsureSudoSaysSoWithNoKnownPackageManager(t *testing.T) {
	err := ensureSudo(func() bool { return false }, "", func(string, ...string) error { return nil })

	if err == nil {
		t.Fatal("expected setup to stop when it cannot install sudo")
	}
}
