//go:build linux

package confedit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// AccessFromKeyFiles counts the ways into this machine from a list of
// authorized_keys paths.
//
// The split matters. /etc/passwd is world-readable, so the agent already knows
// every account, its home and its shell without any privilege at all. The only
// thing it cannot do unprivileged is look inside a home directory. So that one
// step is the only thing granted — `find … -name authorized_keys -size +0` —
// and the judgement happens here, as an ordinary user.
//
// This replaced `ghostpsy read-ssh-access`, which did the whole job as root and
// told a reviewer nothing about what it read.
//
// The grant searches /root and /home. An account whose home is somewhere else is
// not counted, and that is the safe direction to be wrong in: a key we miss
// makes this machine look like it has fewer ways in, so a hardening change is
// refused rather than allowed. Being refused costs a message; being allowed
// wrongly costs the server.
func AccessFromKeyFiles(passwdContent string, keyFiles []string) Access {
	homesWithKeys := homesOf(keyFiles)

	var access Access
	scanner := bufio.NewScanner(strings.NewReader(passwdContent))
	for scanner.Scan() {
		name, home, shell, ok := passwdFields(scanner.Text())
		if !ok || !canLogIn(shell) {
			continue
		}
		if _, found := homesWithKeys[filepath.Clean(home)]; !found {
			continue
		}
		access.AccountsWithKeys++
		if name != "root" {
			access.NonRootAccountsWithKeys++
		}
	}
	return access
}

// homesOf turns /home/bob/.ssh/authorized_keys into /home/bob, so the paths can
// be matched against the homes /etc/passwd lists.
func homesOf(keyFiles []string) map[string]struct{} {
	homes := make(map[string]struct{}, len(keyFiles))
	for _, path := range keyFiles {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		// .../<home>/.ssh/authorized_keys — up two levels is the home.
		home := filepath.Dir(filepath.Dir(path))
		if filepath.Base(filepath.Dir(path)) != ".ssh" {
			continue
		}
		homes[filepath.Clean(home)] = struct{}{}
	}
	return homes
}

// ReadPasswd returns /etc/passwd. It is world-readable on every Linux system,
// so this needs no privilege and must never be granted any.
func ReadPasswd() (string, error) {
	content, err := os.ReadFile(passwdPath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// passwdPath is the account list. Named here so a test can point elsewhere.
const passwdPath = "/etc/passwd"
