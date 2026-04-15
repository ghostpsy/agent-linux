//go:build linux

package identity

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestEntriesFromMap_noDuplicates(t *testing.T) {
	t.Parallel()
	m := map[int][]string{
		0:    {"root"},
		1000: {"alice"},
	}
	got := entriesFromMap(m)
	if len(got) != 0 {
		t.Fatalf("expected no duplicates, got %d entries", len(got))
	}
}

func TestEntriesFromMap_withDuplicates(t *testing.T) {
	t.Parallel()
	m := map[int][]string{
		0:    {"root", "toor"},
		1000: {"alice"},
		1001: {"bob", "bob2", "bob3"},
	}
	got := entriesFromMap(m)
	if len(got) != 2 {
		t.Fatalf("expected 2 duplicate entries, got %d", len(got))
	}
	// entries should be sorted by ID
	if got[0].ID != 0 {
		t.Fatalf("expected first entry ID=0, got %d", got[0].ID)
	}
	if got[1].ID != 1001 {
		t.Fatalf("expected second entry ID=1001, got %d", got[1].ID)
	}
}

func TestEntriesFromMap_capsNamesAtMax(t *testing.T) {
	t.Parallel()
	m := map[int][]string{
		0: {"a", "b", "c", "d", "e", "f"},
	}
	got := entriesFromMap(m)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if len(got[0].Names) > maxDuplicateNames {
		t.Fatalf("expected at most %d names, got %d", maxDuplicateNames, len(got[0].Names))
	}
}

func TestEntriesFromMap_empty(t *testing.T) {
	t.Parallel()
	got := entriesFromMap(map[int][]string{})
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestUniqueSortedNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"b", "a", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "b"}, []string{"a", "b"}},
		{[]string{"", "a", ""}, []string{"a"}},
		{nil, []string{}},
		{[]string{}, []string{}},
	}
	for _, tc := range cases {
		got := uniqueSortedNames(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("uniqueSortedNames(%v): got %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("uniqueSortedNames(%v)[%d]: got %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestEntriesFromMap_sortedOutput(t *testing.T) {
	t.Parallel()
	m := map[int][]string{
		500: {"x", "y"},
		100: {"a", "b"},
		300: {"m", "n"},
	}
	got := entriesFromMap(m)
	want := []payload.DuplicateIDEntry{
		{ID: 100, Names: []string{"a", "b"}},
		{ID: 300, Names: []string{"m", "n"}},
		{ID: 500, Names: []string{"x", "y"}},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Fatalf("entry[%d].ID: got %d, want %d", i, got[i].ID, want[i].ID)
		}
	}
}
