//go:build linux

package collect

import "testing"

func TestRedactCmdline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"python /home/alice/app/run.py", "python [redacted]/app/run.py"},
		{"normal /usr/bin/sh", "normal /usr/bin/sh"},
	}
	for _, tc := range cases {
		got := RedactCmdline(tc.in)
		if got != tc.want {
			t.Fatalf("RedactCmdline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
