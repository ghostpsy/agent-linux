//go:build linux

package privexec

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// Writing a setting is an `install` of a shipped file, so the grant can name both
// paths exactly. The four `write-config --key=* --value=*` lines this replaces were
// wildcards, and a wildcard in a sudoers argument matches `/` as well — measured, it
// read a 0600 file two directories up. See
// internal-doc/solve-explicit-sudoers-design.md.

func TestEveryChangeHasAnInstallCommandNamingBothPaths(t *testing.T) {
	for _, c := range confedit.Changes() {
		id := InstallDropIn(c)
		declared, ok := registry[id]
		if !ok {
			t.Errorf("%s=%s has no declared command, so the fix cannot run",
				c.Setting.Key, c.Value)
			continue
		}
		if len(declared.Params) != 0 {
			t.Errorf("%s has a parameter, so its grant would need a wildcard", id)
		}
		for _, path := range []string{c.DropIn().Source, c.DropIn().Dest} {
			if !slices.Contains(declared.Args, path) {
				t.Errorf("%s does not name %q in its arguments: %v", id, path, declared.Args)
			}
		}
	}
}

func TestEverySettingHasARemoveCommandForTheUndo(t *testing.T) {
	for _, c := range confedit.Changes() {
		id := RemoveDropIn(c.Setting)
		declared, ok := registry[id]
		if !ok {
			t.Fatalf("%s cannot be undone: no declared command", c.Setting.Key)
		}
		if !slices.Contains(declared.Args, c.DropIn().Dest) {
			t.Errorf("%s removes %v, not %q", id, declared.Args, c.DropIn().Dest)
		}
	}
}

// The one that would bite on a customer's server rather than in CI: a grant naming
// a source file the installer never writes is a fix that fails at the moment
// somebody approves it.
func TestEveryInstallSourceIsAFileTheInstallerWrites(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"/etc/ssh/sshd_config.d", "/etc/apt/apt.conf.d"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	written, err := confedit.WriteDropIns(root)
	if err != nil {
		t.Fatal(err)
	}

	onDisk := map[string]bool{}
	for _, path := range written {
		onDisk[strings.TrimPrefix(path, root)] = true
	}

	for _, c := range confedit.Changes() {
		if !onDisk[c.DropIn().Source] {
			t.Errorf("the grant for %s=%s names %q, which the installer does not write",
				c.Setting.Key, c.Value, c.DropIn().Source)
		}
	}
}

// This walks the registry rather than the rendered file, and the difference matters.
//
// The first version of this test read Sudoers() output and passed while four wildcard
// grants were still declared: Sudoers skips a command whose binary is absent, and
// /usr/local/bin/ghostpsy does not exist in a test container. It was measuring the
// container, not the design.
func TestNoDeclaredConfigCommandContainsAWildcard(t *testing.T) {
	// Every configuration command, with nothing left out. It was once scoped to
	// install and remove, because four older grants — config.apply, config.preview,
	// config.restore, config.verify — took the setting and the value as parameters
	// and so said only "any setting, any value" in the file. They are gone, and this
	// test is what stops them coming back.
	for id, declared := range registry {
		if !strings.HasPrefix(string(id), "config.") {
			continue
		}
		for _, arg := range declared.Args {
			if strings.ContainsAny(arg, "*?") {
				t.Errorf("%s takes %q, so its grant is a pattern rather than an exact command", id, arg)
			}
		}
		if len(declared.Params) != 0 {
			t.Errorf("%s has a parameter, and a filled-in parameter is a wildcard in the grant", id)
		}
	}
}

// The grant file says it "grants nothing for software you do not have", and that has
// to stay true for a destination as well as for a binary.
//
// Found on rocky-9: it has no /etc/apt/apt.conf.d, but `install` exists everywhere,
// so the two apt grants were written on a machine where they can never apply.
func TestAGrantIsNotWrittenWhenItsDestinationDirectoryIsAbsent(t *testing.T) {
	present := filepath.Dir(t.TempDir())
	declareForTest(t, ID("test:needs-present"), Command{
		Binary:    "/bin/echo",
		Args:      []string{"here"},
		NeedsPath: present,
	})
	declareForTest(t, ID("test:needs-absent"), Command{
		Binary:    "/bin/echo",
		Args:      []string{"nowhere"},
		NeedsPath: "/etc/definitely-not-a-directory-on-this-host",
	})

	got := Sudoers("ghostpsy")

	if !strings.Contains(got, "/bin/echo here") {
		t.Error("a command whose destination exists was left out of the grant")
	}
	if strings.Contains(got, "/bin/echo nowhere") {
		t.Error("a command whose destination is absent was granted anyway")
	}
}

func TestEveryDropInGrantDependsOnItsDestinationDirectory(t *testing.T) {
	for _, c := range confedit.Changes() {
		wantDir := filepath.Dir(c.DropIn().Dest)
		for _, id := range []ID{InstallDropIn(c), RemoveDropIn(c.Setting)} {
			if got := registry[id].NeedsPath; got != wantDir {
				t.Errorf("%s depends on %q, want %q", id, got, wantDir)
			}
		}
	}
}

// A setting must name the command that can answer for it.
//
// settingTookEffect used to name SSHEffectiveConfig itself, so "did the change take
// effect?" was a question only an SSH setting could be asked. apt has an answer too,
// and it is the setting's style that knows which.
func TestEachStyleNamesTheCommandThatAnswersForIt(t *testing.T) {
	for _, change := range confedit.Changes() {
		id := EffectiveConfig(change.Setting)
		if !Declared(id) {
			t.Errorf("%s answers with %q, which is not declared", change.Setting.Key, id)
		}
		if change.Setting.Style == confedit.StyleSSH && id != SSHEffectiveConfig {
			t.Errorf("%s is an SSH setting and answers with %q", change.Setting.Key, id)
		}
		if change.Setting.Style == confedit.StyleAPTConf && id != APTEffectiveConfig {
			t.Errorf("%s is an apt setting and answers with %q", change.Setting.Key, id)
		}
	}
}
