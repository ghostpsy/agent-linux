//go:build linux

package confedit

import (
	"strings"
	"testing"
)

// OpenSSH accepts `prohibit-password` and reports it back as `without-password`.
// They are the same setting: the second is the older name for the first, and
// `sshd -T` prints whichever the build prefers.
//
// Found on a real machine, on the first end-to-end run. The fix applied cleanly,
// sshd accepted the config, the reload worked — and then the check said:
//
//	the SSH server did not take the change: it is running with
//	PermitRootLogin without-password, not PermitRootLogin prohibit-password
//
// So the change was rolled back for no reason. Everything about that rollback
// worked, which is why this was safe to find on a real server rather than
// expensive. But a check that fails on a correct machine makes the whole feature
// useless: `prohibit-password` is the value we would recommend most often.
func TestTheCheckKnowsProhibitPasswordAndWithoutPasswordAreTheSameThing(t *testing.T) {
	setting := sshSetting(t)

	// Exactly what sshd -T printed on Debian 13.
	effective := "port 22\npermitrootlogin without-password\nx11forwarding no\n"

	if !matchesEffective(setting, "prohibit-password", effective) {
		t.Fatal("a server running without-password is running prohibit-password")
	}
	if !matchesEffective(setting, "without-password", effective) {
		t.Fatal("the older name has to be accepted for itself too")
	}
}

// The synonym must not become a way of accepting the wrong answer.
func TestTheCheckStillRefusesASettingThatReallyDidNotTake(t *testing.T) {
	setting := sshSetting(t)

	if matchesEffective(setting, "prohibit-password", "permitrootlogin yes\n") {
		t.Fatal("a server running 'yes' has not taken 'prohibit-password'")
	}
	if matchesEffective(setting, "no", "permitrootlogin without-password\n") {
		// 'no' is stricter than 'without-password'. Treating them as equal would
		// report a server as hardened when root can still log in with a key.
		t.Fatal("'without-password' must not be accepted as 'no'")
	}
}

func TestTheCheckReadsAnAptSettingBack(t *testing.T) {
	setting := aptSetting(t)
	effective := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`

	if !matchesEffective(setting, "1", effective) {
		t.Fatal("expected the apt setting to be read back")
	}
	if matchesEffective(setting, "1", `APT::Periodic::Unattended-Upgrade "0";`+"\n") {
		t.Fatal("expected a value of 0 not to count as 1")
	}
}

// Whatever the server does think has to reach the person, or a failed check is
// just "it did not work".
func TestAFailedCheckSaysWhatTheServerIsActuallyRunning(t *testing.T) {
	setting := sshSetting(t)

	message := explainMismatch(setting, "no", "permitrootlogin yes\n")

	if !strings.Contains(message, "PermitRootLogin yes") {
		t.Fatalf("expected the message to name what the server is running, got %q", message)
	}
}
