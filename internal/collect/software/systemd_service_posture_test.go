//go:build linux

package software

import "testing"

func TestMapSystemdActiveStateForPosture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"active", "running"},
		{"Active", "running"},
		{"active/running", "running"},
		{"active/reloading", "running"},
		{"reloading", "running"},
		{"inactive", "stopped"},
		{"inactive/dead", "stopped"},
		{"failed", "stopped"},
		{"activating", "unknown"},
		{"", ""},
	}
	for _, tc := range cases {
		got := mapSystemdActiveStateForPosture(tc.in)
		if got != tc.want {
			t.Fatalf("mapSystemdActiveStateForPosture(%q): got %q want %q", tc.in, got, tc.want)
		}
	}
}
