//go:build linux

package privexec

import (
	"os"
	"path/filepath"
	"testing"
)

// Which variant of an action a machine gets is decided by asking whether a binary is
// installed. That question has to be asked about the same directories sudo will search,
// because sudo is what runs the answer.
//
// The old answer came from exec.LookPath, which reads the caller's PATH. That is the
// same mistake that produced 20 grant lines nobody could match: on rocky-9 the agent
// user's PATH starts /sbin:/bin and root's starts /usr/sbin:/usr/bin. Here it decides
// which command runs on a customer's server, so a wrong answer is not a cosmetic one.
func TestInstalledIgnoresTheCallersPath(t *testing.T) {
	elsewhere := t.TempDir()
	fake := filepath.Join(elsewhere, "definitely-not-a-real-binary")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", elsewhere)

	if Installed("definitely-not-a-real-binary") {
		t.Error("a binary sudo would never find must not count as installed")
	}
	// And the other half: an empty PATH must not hide what is really there.
	t.Setenv("PATH", "")
	if !Installed("sh") {
		t.Error("sh is in every Linux image, and the caller's PATH must not decide that")
	}
}

// An absolute path is checked as given, because that is what the grant pins.
func TestInstalledChecksAnAbsolutePathAsGiven(t *testing.T) {
	if Installed("/definitely/not/here") {
		t.Error("a missing absolute path is not installed")
	}
}
