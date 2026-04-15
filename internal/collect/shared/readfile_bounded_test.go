//go:build linux

package shared

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileBounded_fullRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileBounded(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestReadFileBounded_truncated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("hello world, this is a longer string")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileBounded(path, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestReadFileBounded_missingFile(t *testing.T) {
	t.Parallel()
	_, err := ReadFileBounded("/nonexistent/path/file.txt", 1024)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadFileBounded_emptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileBounded(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty content, got %d bytes", len(got))
	}
}

func TestDefaultConfigFileReadLimit(t *testing.T) {
	t.Parallel()
	if DefaultConfigFileReadLimit != 96<<10 {
		t.Fatalf("expected 96KiB, got %d", DefaultConfigFileReadLimit)
	}
}
