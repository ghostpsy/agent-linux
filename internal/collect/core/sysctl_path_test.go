//go:build linux

package core

import "testing"

func TestSysctlDotToProcPath(t *testing.T) {
	if p := sysctlDotToProcPath("net.ipv4.ip_forward"); p != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatalf("got %q", p)
	}
	if sysctlDotToProcPath("") != "" {
		t.Fatal("expected empty")
	}
	if sysctlDotToProcPath("x") != "" {
		t.Fatal("expected empty for short key")
	}
}
