//go:build linux

package privexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustGoThroughTheGate are the packages that change a customer's server.
//
// Everything they run has to be declared here, because the grant file is generated
// from what is declared. A command run any other way is invisible: it appears in no
// grant, `ghostpsy sudoers` does not list it, and the promise that the sudo rule is
// the whole list of what we do stops being true.
var mustGoThroughTheGate = []string{"../action", "../confedit"}

// Two such commands were found by reading the code, not by any test: confedit ran
// `sshd -T` and `apt-config dump` directly. Both needed root, neither was declared,
// and both had been there since the day the grant file was written.
func TestNoPackageThatChangesAServerRunsACommandItself(t *testing.T) {
	for _, dir := range mustGoThroughTheGate {
		for _, path := range goSourceFiles(t, dir) {
			body, err := os.ReadFile(path) //nolint:gosec // a path this test just listed
			if err != nil {
				t.Fatal(err)
			}
			for number, line := range strings.Split(string(body), "\n") {
				// LookPath asks whether a program is installed. It starts nothing,
				// so it is not a way around the gate.
				if strings.Contains(line, "exec.Command") {
					t.Errorf("%s:%d runs a command directly, so it is in no grant:\n\t%s",
						path, number+1, strings.TrimSpace(line))
				}
			}
		}
	}
}

// goSourceFiles lists the package's own code. Tests are left out: a test may run
// anything, because a test does not run on a customer's server.
func goSourceFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		found = append(found, filepath.Join(dir, name))
	}
	if len(found) == 0 {
		t.Fatalf("no source found in %s, so this test would pass by looking at nothing", dir)
	}
	return found
}
