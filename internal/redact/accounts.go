//go:build linux

package redact

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// passwdPath is where the account names come from. It is world-readable on every
// distribution, so this needs no privilege and no sudo grant.
const passwdPath = "/etc/passwd"

// firstPersonUID is where people start.
//
// Every distribution reserves the numbers below this for services — postgres,
// www-data, nginx. Those are not personal data, and masking them would take away the
// information a person needs to judge a change ("this file is owned by postgres")
// while protecting nobody.
const firstPersonUID = 1000

// notPeople are accounts above firstPersonUID that are still not anybody.
//
// nobody is 65534 by convention, and "owned by nobody" is a sentence a sysadmin needs
// to be able to read.
var notPeople = map[string]bool{"nobody": true, "nogroup": true, "root": true}

// Accounts are the names of the people who have an account on this machine.
func Accounts() ([]string, error) {
	return accountsIn(passwdPath)
}

// accountsIn takes the path so a test can describe a machine's accounts exactly.
func accountsIn(path string) ([]string, error) {
	file, err := os.Open(path) //nolint:gosec // a fixed path, or a test's own file
	if err != nil {
		return nil, fmt.Errorf("could not read the list of accounts from %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	var names []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, ok, err := personOnLine(scanner.Text())
		if err != nil {
			return nil, err
		}
		if ok {
			names = append(names, name)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the list of accounts from %s: %w", path, err)
	}
	return names, nil
}

// personOnLine reads one passwd line and says whether it names a person.
func personOnLine(line string) (string, bool, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 3 {
		// A blank line or a comment. Not a failure.
		return "", false, nil
	}

	name := fields[0]
	uid, err := mustParseUID(fields[2])
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", passwdPath, err)
	}
	if uid < firstPersonUID || notPeople[name] {
		return "", false, nil
	}
	return name, true, nil
}
