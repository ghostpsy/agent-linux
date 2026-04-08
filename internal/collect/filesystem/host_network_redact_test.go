//go:build linux

package filesystem

import (
	"net"
	"testing"
)

func TestRedactIPForDisplay(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"172.18.0.4", "172.18.x.x"},
		{"10.0.255.1", "10.0.x.x"},
		{"2001:db8::1", "2001:db8:x:x:x:x:x:x"},
		{"fe80::1", "fe80:0:x:x:x:x:x:x"},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.raw)
		if ip == nil {
			t.Fatalf("parse IP %q", tc.raw)
		}
		if got := redactIPForDisplay(ip); got != tc.want {
			t.Fatalf("redactIPForDisplay(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	if got := redactIPForDisplay(nil); got != "" {
		t.Fatalf("redactIPForDisplay(nil) = %q, want empty", got)
	}
}
