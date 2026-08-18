//go:build linux

package confedit

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped files are written by the installer, which runs as root. Their whole
// value is that the ghostpsy user cannot change them afterwards — otherwise a
// compromised agent rewrites the content and asks root to install it, and the grant
// bounds the destination while the content goes anywhere.

func TestWriteDropInsCreatesOneFilePerChange(t *testing.T) {
	root := rootWithBothDirs(t)

	written, err := WriteDropIns(root)
	if err != nil {
		t.Fatalf("writing the shipped files failed: %v", err)
	}
	if len(written) != len(Changes()) {
		t.Fatalf("wrote %d files for %d changes", len(written), len(Changes()))
	}

	for _, c := range Changes() {
		path := filepath.Join(root, c.DropIn().Source)
		content, err := os.ReadFile(path) //nolint:gosec // a path this test built
		if err != nil {
			t.Errorf("%s=%s: %v", c.Setting.Key, c.Value, err)
			continue
		}
		if string(content) != c.DropIn().Content {
			t.Errorf("%s=%s content is %q, want %q",
				c.Setting.Key, c.Value, content, c.DropIn().Content)
		}
	}
}

func TestShippedFilesCannotBeChangedByTheAgent(t *testing.T) {
	root := rootWithBothDirs(t)
	if _, err := WriteDropIns(root); err != nil {
		t.Fatal(err)
	}

	for _, c := range Changes() {
		info, err := os.Stat(filepath.Join(root, c.DropIn().Source))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o222 != 0 {
			t.Errorf("%s=%s is mode %04o, so it is writable — the content is no longer fixed",
				c.Setting.Key, c.Value, perm)
		}
	}
}

func TestWritingTwiceIsSafe(t *testing.T) {
	// An agent upgrade runs this again, over files that are deliberately read-only.
	// A plain write would fail on the second run.
	root := rootWithBothDirs(t)
	if _, err := WriteDropIns(root); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDropIns(root); err != nil {
		t.Fatalf("the second run failed, so an agent upgrade would fail: %v", err)
	}
}

// The same rule as the grant file: nothing shipped for software this server does not
// have. rocky-9 has no /etc/apt/apt.conf.d, so the two apt files would sit there
// forever, unusable, and `ghostpsy dropins` would offer them.
func TestOnlyFilesThisServerCanUseAreShipped(t *testing.T) {
	root := t.TempDir()
	// An SSH drop-in directory, and deliberately no apt one.
	if err := os.MkdirAll(filepath.Join(root, sshDropInDir), 0o755); err != nil {
		t.Fatal(err)
	}

	applicable := Applicable(root)
	if len(applicable) == 0 {
		t.Fatal("nothing was applicable, so no fix could be offered at all")
	}
	for _, c := range applicable {
		if c.Setting.Style == StyleAPTConf {
			t.Errorf("%s=%s was offered on a server with no apt.conf.d",
				c.Setting.Key, c.Value)
		}
	}

	written, err := WriteDropIns(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != len(applicable) {
		t.Errorf("wrote %d files for %d applicable changes", len(written), len(applicable))
	}
}

// rootWithBothDirs is a server that has somewhere to put every kind of drop-in.
func rootWithBothDirs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{sshDropInDir, aptDropInDir} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
