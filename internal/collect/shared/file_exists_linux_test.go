//go:build linux

package shared

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExistsRegular_existingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !FileExistsRegular(path) {
		t.Fatalf("expected true for existing file %s", path)
	}
}

func TestFileExistsRegular_missingFile(t *testing.T) {
	t.Parallel()
	if FileExistsRegular("/nonexistent/path/no_such_file.txt") {
		t.Fatal("expected false for missing file")
	}
}

func TestFileExistsRegular_directory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if FileExistsRegular(dir) {
		t.Fatal("expected false for directory")
	}
}
