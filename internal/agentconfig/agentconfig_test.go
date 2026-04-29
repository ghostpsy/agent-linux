package agentconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func setPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.conf")
	t.Setenv(envPathOverride, p)
	return p
}

func TestLoad_MissingFileReturnsErrNotConfigured(t *testing.T) {
	setPath(t)
	if _, err := Load(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	setPath(t)
	if err := Save("secret-token-abc"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "secret-token-abc" {
		t.Fatalf("got %q want %q", got, "secret-token-abc")
	}
}

func TestSave_WritesMode0600(t *testing.T) {
	p := setPath(t)
	if err := Save("tok"); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode %#o want %#o", mode, 0o600)
	}
}

func TestLoad_RefusesLoosePermissions(t *testing.T) {
	p := setPath(t)
	if err := os.WriteFile(p, []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error for 0644 perms")
	}
}

func TestSave_RejectsEmpty(t *testing.T) {
	setPath(t)
	if err := Save(""); err == nil {
		t.Fatal("expected error on empty token")
	}
	if err := Save("   \n  "); err == nil {
		t.Fatal("expected error on whitespace-only token")
	}
}

func TestLoad_RejectsEmptyFile(t *testing.T) {
	p := setPath(t)
	if err := os.WriteFile(p, []byte("\n   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error on empty file")
	}
}

func TestSave_OverwritesExisting(t *testing.T) {
	setPath(t)
	if err := Save("first"); err != nil {
		t.Fatal(err)
	}
	if err := Save("second"); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("got %q want %q", got, "second")
	}
}

func TestExists_FalseWhenMissing(t *testing.T) {
	setPath(t)
	if Exists() {
		t.Fatal("expected Exists() == false when file is missing")
	}
}

func TestExists_TrueAfterSave(t *testing.T) {
	setPath(t)
	if err := Save("tok"); err != nil {
		t.Fatal(err)
	}
	if !Exists() {
		t.Fatal("expected Exists() == true after Save")
	}
}
