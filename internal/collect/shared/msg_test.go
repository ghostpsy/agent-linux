//go:build linux

package shared

import (
	"strings"
	"testing"
)

func TestCollectionNote_shortDetail(t *testing.T) {
	t.Parallel()
	note := CollectionNote("file not found")
	if !strings.HasPrefix(note, "No information extracted.") {
		t.Fatalf("expected prefix 'No information extracted.', got %q", note)
	}
	if !strings.Contains(note, "file not found") {
		t.Fatalf("expected detail in note, got %q", note)
	}
}

func TestCollectionNote_truncatesLongDetail(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 500)
	note := CollectionNote(long)
	// prefix "No information extracted. " = 26 chars + 400 chars max detail
	if len(note) > 26+400 {
		t.Fatalf("note too long: %d chars", len(note))
	}
}

func TestCollectionNote_emptyDetail(t *testing.T) {
	t.Parallel()
	note := CollectionNote("")
	if note != "No information extracted. " {
		t.Fatalf("unexpected note for empty detail: %q", note)
	}
}
