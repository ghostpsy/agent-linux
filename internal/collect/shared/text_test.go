//go:build linux

package shared

import "testing"

func TestTruncateRunes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"", 5, ""},
		{"café", 3, "caf"},
		{"日本語テスト", 3, "日本語"},
		{"日本語テスト", 100, "日本語テスト"},
	}
	for _, tc := range cases {
		got := TruncateRunes(tc.in, tc.max)
		if got != tc.want {
			t.Fatalf("TruncateRunes(%q, %d): got %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
