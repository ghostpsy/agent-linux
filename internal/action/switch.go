//go:build linux

package action

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The machine owner has the last word.
//
// A person with root on their own server must be able to stop ghostpsy changing
// it, without asking us, without an account, and without the network. A file is
// the right shape for that: it needs nothing but a shell, it survives a reboot,
// and it cannot be undone from the cloud.
//
// It stops the dry run too. Somebody who switched Solve off did not ask for a
// preview either, and a preview is work the machine has to do.

// SwitchFileName is what a sysadmin creates to stop the agent changing anything.
const SwitchFileName = "solve.disabled"

// ProtectedFileName lists services ghostpsy must never touch, one per line.
//
// A finer tool than the switch above: somebody who is happy for ghostpsy to
// restart nginx may still want it nowhere near their database.
const ProtectedFileName = "/etc/ghostpsy/protected-services"

// configDir is where the agent's own files live. Tests redirect it.
func configDir() string {
	if dir := strings.TrimSpace(os.Getenv("GHOSTPSY_CONFIG_DIR")); dir != "" {
		return dir
	}
	return "/etc/ghostpsy"
}

// switchPath is where the switch lives, next to the agent's own config.
func switchPath() string {
	return filepath.Join(configDir(), SwitchFileName)
}

// Protected reads the services this machine's owner has put out of bounds.
//
// A missing file means nothing is protected, which is the normal case. An
// unreadable one is an error and stays an error: guessing "probably nothing" about
// a list whose whole purpose is to stop us touching something is not a guess we
// are entitled to make.
func Protected() ([]string, error) {
	path := filepath.Join(configDir(), filepath.Base(ProtectedFileName))
	content, err := os.ReadFile(path) //nolint:gosec // a fixed path, not caller input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}

	var units []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		units = append(units, line)
	}
	return units, nil
}

// SwitchedOff reports whether this machine's owner has turned actions off, and
// says so in words a person can read.
//
// Anything the file contains is passed back as the reason, so a sysadmin can
// leave a note for whoever reads the dashboard: "frozen until the audit is over".
func SwitchedOff() (bool, string) {
	path := switchPath()
	content, err := os.ReadFile(path) //nolint:gosec // a fixed path, not caller input
	if err != nil {
		// Absent is the normal case. Anything else — a permission problem, a
		// directory in its place — is treated as switched off, because the one
		// mistake we must never make is changing a server whose owner told us
		// not to.
		if os.IsNotExist(err) {
			return false, ""
		}
		return true, fmt.Sprintf(
			"ghostpsy could not read %s, so it is treating this machine as switched off", path)
	}

	reason := strings.TrimSpace(string(content))
	if reason == "" {
		return true, fmt.Sprintf(
			"Actions are switched off on this machine: %s exists. "+
				"Delete that file to let ghostpsy make changes again.", path)
	}
	return true, fmt.Sprintf(
		"Actions are switched off on this machine: %s says %q. "+
			"Delete that file to let ghostpsy make changes again.", path, reason)
}
