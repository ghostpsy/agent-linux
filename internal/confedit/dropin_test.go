//go:build linux

package confedit

import (
	"strings"
	"testing"
)

// A drop-in file is how a setting is written on a normal server: we create a whole
// file of our own instead of editing one somebody else owns. That is what lets the
// sudo grant name both the source and the destination, with no wildcard — the
// content is fixed by root at install time, so there is nothing left to decide when
// the command runs.

func TestDropInSourceNamesTheSettingAndItsValue(t *testing.T) {
	// One source file per setting-and-value pair. The name is the change, so the
	// grant line says what it does without a comment.
	for _, c := range Changes() {
		want := c.Setting.Key + "=" + c.Value + ".conf"
		if !strings.HasSuffix(c.DropIn().Source, "/"+want) {
			t.Errorf("%s=%s has source %q, which does not end in %q",
				c.Setting.Key, c.Value, c.DropIn().Source, want)
		}
	}
}

func TestSSHDropInIsReadBeforeTheDistrosOwnFiles(t *testing.T) {
	// Measured on debian-13 and rocky-9: sshd keeps the FIRST value it sees, the
	// distros ship 50-cloud-init.conf and 50-redhat.conf, and a 10- file beat a
	// 99- one. So ours has to sort below 50.
	c := changeFor(t, "ssh.max_auth_tries", "5")
	got := c.DropIn().Dest
	want := "/etc/ssh/sshd_config.d/10-ghostpsy-max-auth-tries.conf"
	if got != want {
		t.Errorf("destination is %q, want %q", got, want)
	}
}

func TestAPTDropInIsReadAfterTheDistrosOwnFiles(t *testing.T) {
	// Measured: apt is the opposite of sshd. The LAST file wins, so ours sorts high.
	c := changeFor(t, "apt.unattended_upgrade", "1")
	got := c.DropIn().Dest
	want := "/etc/apt/apt.conf.d/99-ghostpsy-unattended-upgrade.conf"
	if got != want {
		t.Errorf("destination is %q, want %q", got, want)
	}
}

func TestEveryDropInPathEndsInConf(t *testing.T) {
	// Measured: apt ignores a file in apt.conf.d unless it has no extension or
	// ends in .conf. A file named 99-ghostpsy.disabled was silently not read, so
	// the wrong name means the fix reports success and changes nothing.
	for _, c := range Changes() {
		for _, path := range []string{c.DropIn().Source, c.DropIn().Dest} {
			if !strings.HasSuffix(path, ".conf") {
				t.Errorf("%s=%s uses %q, which apt would ignore", c.Setting.Key, c.Value, path)
			}
		}
	}
}

func TestDropInContentSetsExactlyThatValue(t *testing.T) {
	for _, c := range Changes() {
		got, found := Value(c.Setting, c.DropIn().Content)
		if !found {
			t.Errorf("%s=%s wrote a file that does not set the directive at all:\n%s",
				c.Setting.Key, c.Value, c.DropIn().Content)
			continue
		}
		if got != c.Value {
			t.Errorf("%s=%s wrote %q instead", c.Setting.Key, c.Value, got)
		}
	}
}

func TestOneDestinationPerSettingSoUndoIsOneRemoval(t *testing.T) {
	// Every value of a setting goes to the same file, so undo is `rm` of one exact
	// path and the other settings are untouched. Two settings sharing a file would
	// make undoing one of them rewrite the other.
	destOf := map[string]string{}
	settingOf := map[string]string{}
	for _, c := range Changes() {
		dest := c.DropIn().Dest
		if seen, ok := destOf[c.Setting.Key]; ok && seen != dest {
			t.Errorf("%s writes to both %q and %q, so one rm cannot undo it",
				c.Setting.Key, seen, dest)
		}
		destOf[c.Setting.Key] = dest

		if owner, ok := settingOf[dest]; ok && owner != c.Setting.Key {
			t.Errorf("%s and %s share %q, so undoing one would rewrite the other",
				owner, c.Setting.Key, dest)
		}
		settingOf[dest] = c.Setting.Key
	}
}

func TestNoDropInPathContainsACharacterSudoTreatsAsAWildcard(t *testing.T) {
	// The whole design rests on the grant being literal. A `*`, `?` or `[` in a
	// path would turn one exact grant into a pattern, and a pattern in a sudoers
	// argument matches `/` too — measured: it read a 0600 file two directories up.
	for _, c := range Changes() {
		for _, path := range []string{c.DropIn().Source, c.DropIn().Dest} {
			if strings.ContainsAny(path, "*?[]\\") {
				t.Errorf("%s=%s uses %q, which sudo would read as a pattern",
					c.Setting.Key, c.Value, path)
			}
		}
	}
}

func changeFor(t *testing.T, key, value string) Change {
	t.Helper()
	for _, c := range Changes() {
		if c.Setting.Key == key && c.Value == value {
			return c
		}
	}
	t.Fatalf("%s=%s is not a declared change", key, value)
	return Change{}
}
