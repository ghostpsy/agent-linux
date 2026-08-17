//go:build linux

package confedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withEtc gives the test a private /etc it can write to, and a real sshd_config
// inside it. The edits below are the real ones, on a real file.
func withEtc(t *testing.T, content string) Setting {
	t.Helper()
	root := t.TempDir()
	t.Setenv(envRoot, root)

	s := sshSetting(t)
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(s.File)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, s.File), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPreviewChangesNothingAtAll(t *testing.T) {
	before := "PermitRootLogin yes\n"
	s := withEtc(t, before)

	out, err := Preview(s, "no")

	if err != nil {
		t.Fatalf("expected the preview to work, got %v", err)
	}
	after, err := os.ReadFile(filePath(s))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatalf("the preview modified the file:\n%s", after)
	}
	if !strings.Contains(out, "PermitRootLogin yes") || !strings.Contains(out, "PermitRootLogin no") {
		t.Fatalf("expected the preview to show both the old and the new line, got:\n%s", out)
	}
	if _, err := os.Stat(filePath(s) + BackupSuffix); !os.IsNotExist(err) {
		t.Fatal("the preview took a backup, which means it wrote something")
	}
}

// The whole promise of a reversible action, tested by actually reversing it.
func TestApplyThenRestoreLeavesTheFileExactlyAsItWas(t *testing.T) {
	before := "# a real file\nPort 22\nPermitRootLogin yes\nX11Forwarding yes\n"
	s := withEtc(t, before)

	if _, err := Apply(s, "no"); err != nil {
		t.Fatalf("expected the change to be applied, got %v", err)
	}
	changed, err := os.ReadFile(filePath(s))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(changed), "PermitRootLogin no") {
		t.Fatalf("expected the change to be on disk, got:\n%s", changed)
	}

	if _, err := Restore(s); err != nil {
		t.Fatalf("expected the undo to work, got %v", err)
	}
	restored, err := os.ReadFile(filePath(s))
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != before {
		t.Fatalf("expected the file byte for byte as it was.\nwant:\n%s\ngot:\n%s", before, restored)
	}
}

func TestApplyKeepsThePermissionsTheFileAlreadyHad(t *testing.T) {
	s := withEtc(t, "PermitRootLogin yes\n")
	if err := os.Chmod(filePath(s), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(s, "no"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filePath(s))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected the file to keep mode 0600, got %v", info.Mode().Perm())
	}
}

// A machine that has never had automatic updates set up has no such file. Creating
// it is the fix, not an error.
func TestApplyCreatesAFileThatWasNotThere(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envRoot, root)
	s := aptSetting(t)
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(s.File)), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(s, "1"); err != nil {
		t.Fatalf("expected a missing file to be created, got %v", err)
	}

	content, err := os.ReadFile(filePath(s))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `APT::Periodic::Unattended-Upgrade "1";`) {
		t.Fatalf("expected the setting to be written, got:\n%s", content)
	}
}

// Restoring twice must not claim to have put something back a second time.
func TestRestoreSaysSoWhenThereIsNothingToPutBack(t *testing.T) {
	s := withEtc(t, "PermitRootLogin yes\n")

	if _, err := Restore(s); err == nil {
		t.Fatal("expected an undo with no backup to be refused, not reported as done")
	}

	if _, err := Apply(s, "no"); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(s); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(s); err == nil {
		t.Fatal("expected a second undo to be refused, since the copy is gone")
	}
}

// A change that is already in place must not take a backup: doing so would
// overwrite a real earlier copy with an identical one and lose the undo.
func TestApplyTakesNoBackupWhenThereIsNothingToChange(t *testing.T) {
	s := withEtc(t, "PermitRootLogin no\n")

	if _, err := Apply(s, "no"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filePath(s) + BackupSuffix); !os.IsNotExist(err) {
		t.Fatal("expected no backup when nothing changed")
	}
}
