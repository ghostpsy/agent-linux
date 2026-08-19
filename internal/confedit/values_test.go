//go:build linux

package confedit

import (
	"slices"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/redact"
)

// The grant file, the shipped drop-in files and the API catalogue all need the
// list of values written out one by one. A pattern cannot be enumerated, so the
// list has to be the source of truth rather than a regexp over it.

func TestChangesListsEveryValueOfEverySetting(t *testing.T) {
	changes := Changes()
	if len(changes) == 0 {
		t.Fatal("Changes() returned nothing, so no grant or drop-in file can be generated")
	}

	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.Setting.Key+"="+c.Value] = true
	}

	// MaxAuthTries accepts four values, and every one of them needs its own
	// grant line and its own shipped file.
	for _, value := range []string{"3", "4", "5", "6"} {
		if !seen["ssh.max_auth_tries="+value] {
			t.Errorf("ssh.max_auth_tries=%s is accepted but not listed in Changes()", value)
		}
	}
	if seen["ssh.max_auth_tries=7"] {
		t.Error("ssh.max_auth_tries=7 is not accepted, so it must not be listed")
	}
}

func TestChangesOmitsAdviceOnlySettings(t *testing.T) {
	// ssh.password_authentication is explained but never written by us. A grant
	// line for it would claim a power we deliberately do not have.
	for _, c := range Changes() {
		if c.Setting.Key == "ssh.password_authentication" {
			t.Fatalf("advice-only setting listed as writable, with value %q", c.Value)
		}
	}
}

func TestCheckAcceptsExactlyTheDeclaredValues(t *testing.T) {
	for _, c := range Changes() {
		if _, err := Check(c.Setting.Key, c.Value); err != nil {
			t.Errorf("Check(%s, %s) refused a value Changes() offers: %v",
				c.Setting.Key, c.Value, err)
		}
	}
	if _, err := Check("ssh.max_auth_tries", "7"); err == nil {
		t.Error("Check accepted MaxAuthTries 7, which is outside the declared values")
	}
}

// A setting knows which service reads its file. That replaces the distro branch in
// internal/action/catalog.go, which chose the unit name from /etc/debian_version or
// /etc/redhat-release. The unit name is a fact about the machine, so the machine
// should be asked — not the distribution guessed.
func TestASSHSettingNamesBothUnitNamesForTheServer(t *testing.T) {
	s, _ := Lookup("ssh.max_auth_tries")
	// Debian calls it ssh, the RHEL family calls it sshd. We reload whichever is here.
	for _, want := range []string{"sshd", "ssh"} {
		if !slices.Contains(s.Units, want) {
			t.Errorf("ssh.max_auth_tries does not name the %q unit: %v", want, s.Units)
		}
	}
}

// apt reads its configuration on each periodic run, so nothing has to be reloaded.
// Naming a unit here would grant a restart nobody needs.
func TestAnAPTSettingNamesNoUnit(t *testing.T) {
	s, _ := Lookup("apt.unattended_upgrade")
	if len(s.Units) != 0 {
		t.Errorf("apt.unattended_upgrade asks to reload %v, but apt re-reads its files itself", s.Units)
	}
}

// A setting's value must survive masking untouched.
//
// The report is masked at the moment each command's output is recorded, which means the
// checks that read an earlier step read the masked text. That is safe only while no
// value ghostpsy writes could be mistaken for a name, a key or an address — otherwise
// `settingTookEffect` would compare "4" against a masked "4" and roll back a change
// that worked.
//
// If a future setting takes an address or a user for a value, this test fails and the
// masking has to move to the moment the report is sent instead.
func TestNoValueWeWriteWouldBeChangedByMasking(t *testing.T) {
	people := []string{"edyan", "deploy", "root", "admin"}

	for _, change := range Changes() {
		for _, text := range []string{change.Value, change.Setting.Directive, change.DropIn().Content} {
			if masked := redact.Text(people, text); masked != text {
				t.Errorf("%s: masking turns %q into %q, so a check could not read it back",
					change.Setting.Key, text, masked)
			}
		}
	}
}
