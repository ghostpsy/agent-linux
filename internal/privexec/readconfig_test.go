//go:build linux

package privexec

import (
	"slices"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// The preview is made of real commands now, so it needs three of them: what the
// server has, what we would write, and what the service currently believes.
//
// Reading is privileged on a real machine. Measured as a non-root user: rocky-9 ships
// sshd_config as 0600, and debian-13 ships it 0644 but its 50-cloud-init.conf drop-in
// as 0600 — so both `cat sshd_config` and `sshd -T` failed with "Permission denied".

func TestReadingTheSSHConfigIsDeclaredWithNoWildcard(t *testing.T) {
	declared, ok := registry[ReadSSHConfig]
	if !ok {
		t.Fatal("the preview cannot show what the server has now")
	}
	if declared.Unprivileged {
		t.Error("declared as needing no privilege, but rocky-9 ships sshd_config as 0600")
	}
	if len(declared.Params) != 0 {
		t.Error("takes a parameter, so its grant would be `cat *` — which reads any file on the host")
	}
	if !slices.Contains(declared.Args, "/etc/ssh/sshd_config") {
		t.Errorf("does not name the file: %v", declared.Args)
	}
}

func TestAskingSshdWhatItBelievesIsDeclared(t *testing.T) {
	declared, ok := registry[SSHEffectiveConfig]
	if !ok {
		t.Fatal("nothing can verify a change took effect")
	}
	if declared.Unprivileged {
		t.Error("declared as needing no privilege, but `sshd -T` failed as a normal user on both machines")
	}
	if !slices.Contains(declared.Args, "-T") {
		t.Errorf("does not ask for the effective configuration: %v", declared.Args)
	}
}

// Showing what we would write needs no privilege at all: the shipped files are 0444.
// A grant for reading a world-readable file would be nine lines that buy nothing.
func TestShowingWhatWouldBeWrittenNeedsNoPrivilege(t *testing.T) {
	for _, c := range confedit.Changes() {
		declared, ok := registry[ShowDropIn(c)]
		if !ok {
			t.Errorf("%s=%s cannot be shown before it is approved", c.Setting.Key, c.Value)
			continue
		}
		if !declared.Unprivileged {
			t.Errorf("%s=%s asks for privilege to read a 0444 file", c.Setting.Key, c.Value)
		}
		if !slices.Contains(declared.Args, c.DropIn().Source) {
			t.Errorf("%s=%s shows %v, not the file that would be installed", c.Setting.Key, c.Value, declared.Args)
		}
	}
}

// None of these three may appear in the grant with a wildcard, and `cat` is the one
// that would hurt most: measured on debian-13, `cat /tmp/gpd/*.conf` under a sudoers
// wildcard read a 0600 file two directories up.
func TestNoReadingCommandIsGrantedWithAWildcard(t *testing.T) {
	for id, declared := range registry {
		if declared.Binary != "cat" && declared.Binary != "/usr/bin/cat" {
			continue
		}
		for _, arg := range declared.Args {
			if arg == "*" || arg == "?" {
				t.Errorf("%s reads by pattern, so it can read any file on the host", id)
			}
		}
	}
}
