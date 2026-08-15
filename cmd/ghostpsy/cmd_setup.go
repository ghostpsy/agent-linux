//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// installSudoRule writes the privilege grant, but only after the system's own
// checker has accepted it.
//
// This is the single most dangerous step in the whole install. A malformed file
// in /etc/sudoers.d can lock every administrator out of sudo on the host, and
// the way back in is a rescue boot. So the rule is written to a temporary file,
// checked with visudo, and only then moved into place.
func installSudoRule(dest, rule string, run runner) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".ghostpsy-sudoers-*")
	if err != nil {
		return fmt.Errorf("could not prepare the sudo rule: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.WriteString(rule); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("could not write the sudo rule: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not write the sudo rule: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o440); err != nil {
		return fmt.Errorf("could not set permissions on the sudo rule: %w", err)
	}

	if err := run("visudo", "-c", "-f", tmpPath); err != nil {
		// Deliberately keep the rejected file: it is the only evidence of what
		// went wrong, and this is a bug in ghostpsy, not on the user's server.
		kept := dest + ".rejected"
		_ = os.Rename(tmpPath, kept)
		return fmt.Errorf("the sudo rule did not pass this system's own check, so it was not installed. "+
			"Your sudo setup is untouched. Please send us this file: %s (%w)", kept, err)
	}

	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("could not install the sudo rule: %w", err)
	}
	return os.Chmod(dest, 0o440)
}

// checkSudoersIncludesDropInDir refuses to continue when /etc/sudoers does not
// read the drop-in directory.
//
// Very old sudo ignores /etc/sudoers.d unless the #includedir line is present.
// A grant that looks installed but is never read is worse than no grant,
// because nothing reports it: the agent would simply lose half its data and
// say nothing.
func checkSudoersIncludesDropInDir(sudoersPath string) error {
	b, err := os.ReadFile(sudoersPath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", sudoersPath, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#includedir") || strings.HasPrefix(line, "@includedir") {
			return nil
		}
	}
	return errors.New("this server's /etc/sudoers has no #includedir line, so a rule placed in " +
		"/etc/sudoers.d would never be read. Add `#includedir /etc/sudoers.d` with visudo, then run this again")
}

type runner func(name string, args ...string) error

// installSudoCommands maps a package manager to the command that installs sudo.
// The list is explicit rather than guessed: running an invented command as root
// on someone's server is not something to improvise.
var installSudoCommands = map[string][]string{
	"apt-get": {"apt-get", "install", "-y", "sudo"},
	"dnf":     {"dnf", "install", "-y", "sudo"},
	"yum":     {"yum", "install", "-y", "sudo"},
	"zypper":  {"zypper", "--non-interactive", "install", "sudo"},
	"apk":     {"apk", "add", "--no-cache", "sudo"},
	"pacman":  {"pacman", "-S", "--noconfirm", "sudo"},
}

// ensureSudo makes sure sudo is present, installing it if it is not.
//
// sudo is the mechanism the entire privilege model stands on: the agent reads
// privileged files through it and runs as an unprivileged user otherwise. There
// is no root mode to fall back to, so if this fails the install stops.
//
// In practice the two failure conditions barely overlap. Hosts that lack sudo
// are modern enough for their package manager to work; hosts whose repositories
// are dead are old enough to have shipped sudo already.
func ensureSudo(present func() bool, packageManager string, run runner) error {
	if present() {
		return nil
	}

	argv, known := installSudoCommands[packageManager]
	if !known {
		return errors.New("sudo is not installed on this server and there is no package manager here that " +
			"ghostpsy knows how to use. Install sudo, then run this again. ghostpsy never runs as root, " +
			"so it cannot continue without it")
	}

	if err := run(argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("could not install sudo with %s. This server's package repositories may no longer "+
			"be online, which is a property of the server rather than of ghostpsy. Install sudo yourself, "+
			"then run this again (%w)", packageManager, err)
	}
	return nil
}
