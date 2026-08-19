//go:build linux

package privexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSudoersGrantsOneLinePerDeclaredCommand(t *testing.T) {
	declareForTest(t, ID("test:echo"), Command{Binary: "/bin/echo", Args: []string{"hello"}})

	got := Sudoers("ghostpsy")

	want := "ghostpsy ALL=(root) NOPASSWD: /bin/echo hello"
	if !strings.Contains(got, want) {
		t.Fatalf("expected the grant to contain %q, got:\n%s", want, got)
	}
}

// The file is generated on the host it applies to, so a command whose binary is
// not installed must not be granted. We never hand out privilege for something
// that is not there.
func TestSudoersSkipsCommandsWhoseBinaryIsAbsent(t *testing.T) {
	declareForTest(t, ID("test:absent"), Command{Binary: "/usr/bin/definitely-not-installed"})

	got := Sudoers("ghostpsy")

	if strings.Contains(got, "definitely-not-installed") {
		t.Fatalf("expected an absent binary to be left out of the grant, got:\n%s", got)
	}
}

// sudo deletes the environment. A command that declared one needs a matching
// per-command env_keep line, or it will behave differently under sudo than it
// did in testing — see TestRunAppliesTheDeclaredEnvironment.
func TestSudoersKeepsTheEnvironmentADeclaredCommandNeeds(t *testing.T) {
	declareForTest(t, ID("test:env-keep"), Command{
		Binary: "/bin/echo",
		Args:   []string{"x"},
		Env:    []string{"LC_ALL=C"},
	})

	got := Sudoers("ghostpsy")

	want := `Defaults!/bin/echo env_keep += "LC_ALL"`
	if !strings.Contains(got, want) {
		t.Fatalf("expected the grant to contain %q, got:\n%s", want, got)
	}
}

// The grant file's whole value is that a sysadmin can read it and know what we
// are allowed to do. Every line therefore carries its reason.
func TestSudoersExplainsEachGrantInPlainWords(t *testing.T) {
	declareForTest(t, ID("test:why"), Command{
		Binary: "/bin/echo",
		Args:   []string{"x"},
		Why:    "read the firewall rules",
	})

	got := Sudoers("ghostpsy")

	if !strings.Contains(got, "# read the firewall rules") {
		t.Fatalf("expected the grant to explain itself, got:\n%s", got)
	}
}

// Guards the catalogue itself. A privilege with no stated reason cannot be
// reviewed by the person whose server it applies to, so it must not exist.
func TestEveryCatalogueEntryIsUsableAndExplained(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("the catalogue is empty: no privileged command is declared")
	}
	for id, c := range registry {
		if c.Binary == "" {
			t.Errorf("%s: no binary declared", id)
		}
		if c.Why == "" {
			t.Errorf("%s: no reason declared, so it cannot be explained in the grant file", id)
		}
	}
}

// Several commands share one binary. Repeating its env_keep line once per
// command is noise in a file whose only job is to be read.
func TestSudoersEmitsOneEnvKeepLinePerBinary(t *testing.T) {
	declareForTest(t, ID("test:share-a"), Command{
		Binary: "/bin/echo", Args: []string{"a"}, Env: []string{"LC_ALL=C"}, Why: "a",
	})
	declareForTest(t, ID("test:share-b"), Command{
		Binary: "/bin/echo", Args: []string{"b"}, Env: []string{"LC_ALL=C"}, Why: "b",
	})

	got := Sudoers("ghostpsy")

	if n := strings.Count(got, "Defaults!/bin/echo env_keep"); n != 1 {
		t.Fatalf("expected exactly 1 env_keep line for the shared binary, got %d:\n%s", n, got)
	}
}

// The grant file has to be the same text whoever generates it, or `sudoers --check`
// reports drift that no reinstall can clear.
//
// Measured on rocky-9, where /bin is a symlink to usr/bin: root's PATH begins with
// /usr/sbin:/usr/bin, and the agent user's begins with /sbin:/bin. exec.LookPath
// therefore answered /usr/bin/systemctl for root and /bin/systemctl for the agent —
// the same program, two spellings, and 20 grant lines that never matched.
func TestABinaryResolvesToTheSamePathWhateverTheCallersPATHIs(t *testing.T) {
	odd := t.TempDir()
	if err := os.WriteFile(filepath.Join(odd, "cat"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", odd)
	fromOddPath, err := resolve("cat")
	if err != nil {
		t.Fatalf("a binary that exists has to resolve: %v", err)
	}

	t.Setenv("PATH", "")
	fromNoPath, err := resolve("cat")
	if err != nil {
		t.Fatalf("an empty PATH must not hide a binary that is installed: %v", err)
	}

	if fromOddPath != fromNoPath {
		t.Errorf("the caller's PATH changed where a granted command lives: %q then %q",
			fromOddPath, fromNoPath)
	}
	if strings.HasPrefix(fromOddPath, odd) {
		t.Errorf("a directory on the caller's PATH ended up in the grant: %q", fromOddPath)
	}
}
