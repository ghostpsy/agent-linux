//go:build linux

package filesystem

import "testing"

func TestMountFlagsFromOptions(t *testing.T) {
	n, ns, nx := mountFlagsFromOptions("rw,nodev,nosuid,relatime")
	if !n || !ns || nx {
		t.Fatalf("expected nodev and nosuid true, noexec false, got nodev=%v nosuid=%v noexec=%v", n, ns, nx)
	}
	n, ns, nx = mountFlagsFromOptions("rw,noexec")
	if nx != true || n || ns {
		t.Fatalf("expected noexec only, got nodev=%v nosuid=%v noexec=%v", n, ns, nx)
	}
}
