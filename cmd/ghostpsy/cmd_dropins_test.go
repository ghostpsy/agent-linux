//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// `ghostpsy dropins` answers "what exactly will you put in my sshd_config.d?".
//
// It matters because the sudo grant names these files by path and installs them
// without looking at them. The person judging the grant has to be able to read the
// content it will copy, and the only honest way to show it is to print the files
// that are actually on disk.

func TestDropInsPrintsEveryFileWithItsContent(t *testing.T) {
	root := rootWithDropInDirs(t)
	var out bytes.Buffer
	if err := printDropIns(&out, root); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	for _, c := range confedit.Applicable(root) {
		if !strings.Contains(got, c.DropIn().Source) {
			t.Errorf("%s=%s: the file it installs is not shown", c.Setting.Key, c.Value)
		}
		// Line by line: the output indents file content so it cannot be mistaken
		// for our own prose, so the whole block is not one contiguous string.
		for _, line := range strings.Split(strings.TrimRight(c.DropIn().Content, "\n"), "\n") {
			if !strings.Contains(got, line) {
				t.Errorf("%s=%s: the content line %q is not shown", c.Setting.Key, c.Value, line)
			}
		}
		if !strings.Contains(got, c.DropIn().Dest) {
			t.Errorf("%s=%s: the destination is not shown", c.Setting.Key, c.Value)
		}
	}
}

func TestDropInsPrintingWritesNothing(t *testing.T) {
	// It is the command a cautious person runs first. If it changed the machine it
	// would be the opposite of what it is for.
	root := t.TempDir()
	var out bytes.Buffer
	if err := printDropIns(&out, root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("printing created %d entries", len(entries))
	}
}

func TestDropInsWriteInstallsThemReadOnly(t *testing.T) {
	root := rootWithDropInDirs(t)
	var out bytes.Buffer
	if err := writeDropIns(&out, root); err != nil {
		t.Fatal(err)
	}

	changes := confedit.Applicable(root)
	if len(changes) == 0 {
		t.Fatal("nothing applicable, so this test would prove nothing")
	}
	for _, c := range changes {
		info, err := os.Stat(filepath.Join(root, c.DropIn().Source))
		if err != nil {
			t.Errorf("%s=%s was not written: %v", c.Setting.Key, c.Value, err)
			continue
		}
		if perm := info.Mode().Perm(); perm&0o222 != 0 {
			t.Errorf("%s=%s is mode %04o, so the agent could rewrite what root installs",
				c.Setting.Key, c.Value, perm)
		}
	}
	if !strings.Contains(out.String(), fmt.Sprintf("%d", len(changes))) {
		t.Errorf("the command did not say how many files it wrote:\n%s", out.String())
	}
}

// rootWithDropInDirs is a server with somewhere to put every kind of drop-in. A bare
// temporary directory is a server with nowhere, which is a different test.
func rootWithDropInDirs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"/etc/ssh/sshd_config.d", "/etc/apt/apt.conf.d"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
