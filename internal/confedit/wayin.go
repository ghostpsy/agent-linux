//go:build linux

package confedit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Before ghostpsy closes a door on somebody, it counts the doors that are left.
//
// This exists because of a real lock-out. `PermitRootLogin no` was set on a Rocky 9
// cloud machine where root was the only account with a key, and nobody could log in
// again — while the machine looked completely healthy from outside: sshd running,
// port 22 accepting connections, every login refused. The check that was supposed
// to prevent this only asked whether the port still answered. It did.
//
// So the question has to be about accounts, not ports: after this change, is there
// still somebody who could get in?
//
// Only counts leave this code. No key, no comment and no file name is returned —
// the same rule the shadow and sudoers readers follow.

// Access is how many ways into this machine there are over SSH.
type Access struct {
	// AccountsWithKeys is how many accounts have at least one SSH key.
	AccountsWithKeys int `json:"accounts_with_keys"`

	// NonRootAccountsWithKeys is how many of those are not root. Refusing root
	// logins outright is only safe when this is at least one.
	NonRootAccountsWithKeys int `json:"non_root_accounts_with_keys"`
}

// AllowsChange reports whether this much access is enough for a setting to be
// safe, and says what is missing when it is not.
func (a Access) AllowsChange(need WayIn) (bool, string) {
	switch need {
	case WayInNothing:
		return true, ""
	case WayInAnyKey:
		if a.AccountsWithKeys > 0 {
			return true, ""
		}
		return false, "no account on this server has an SSH key, so this change would leave " +
			"no way to log in at all. Add your key first, then run this again"
	case WayInOtherAccountKey:
		if a.NonRootAccountsWithKeys > 0 {
			return true, ""
		}
		return false, "root is the only account on this server with an SSH key, so refusing " +
			"root logins would lock everybody out"
	}
	return false, "ghostpsy does not know what this change would need to stay safe, so it will not make it"
}

// ReadAccess counts the ways into this machine.
//
// It needs root: an authorized_keys file lives in a home directory this agent
// cannot read. So it is reached the same way /etc/shadow is — through the agent's
// own signed binary, which returns only the counts.
func ReadAccess() (Access, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return Access{}, err
	}
	defer func() { _ = file.Close() }()

	var access Access
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, home, shell, ok := passwdFields(scanner.Text())
		if !ok || !canLogIn(shell) || !hasAnyKey(home) {
			continue
		}
		access.AccountsWithKeys++
		if name != "root" {
			access.NonRootAccountsWithKeys++
		}
	}
	return access, scanner.Err()
}

// AccessJSON is what the delegated read prints.
func AccessJSON() ([]byte, error) {
	access, err := ReadAccess()
	if err != nil {
		return nil, err
	}
	return json.Marshal(access)
}

// passwdFields pulls the name, home and shell out of one /etc/passwd line.
func passwdFields(line string) (name, home, shell string, ok bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 7 || strings.HasPrefix(line, "#") {
		return "", "", "", false
	}
	return parts[0], parts[5], parts[6], true
}

// canLogIn reports whether an account's shell would let it log in at all.
//
// A system account pointing at nologin cannot be a way in, however many keys it
// has — counting it would let a change through on a server nobody can reach.
func canLogIn(shell string) bool {
	shell = strings.TrimSpace(shell)
	if shell == "" {
		return false
	}
	switch filepath.Base(shell) {
	case "nologin", "false", "sync", "shutdown", "halt":
		return false
	}
	return true
}

// hasAnyKey reports whether a home directory holds at least one SSH key.
//
// Comments and blank lines do not count. An authorized_keys file containing only
// "# put your key here" is not a way in, and treating it as one is how a check
// like this passes on exactly the machine it was written to protect.
func hasAnyKey(home string) bool {
	if strings.TrimSpace(home) == "" {
		return false
	}
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		content, err := os.ReadFile(filepath.Join(home, ".ssh", name)) //nolint:gosec // a home from /etc/passwd
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return true
			}
		}
	}
	return false
}
