//go:build linux

package firewall

import "testing"

func TestUfwStatusMeansActive(t *testing.T) {
	t.Parallel()
	if !ufwStatusMeansActive("status: active") {
		t.Fatalf("status: active")
	}
	if ufwStatusMeansActive("status: inactive") {
		t.Fatalf("inactive must lose to active substring check")
	}
	if !ufwStatusMeansActive("status: active\n...") {
		t.Fatalf("multiline active")
	}
}

func TestUfwEnabledFromConfContent(t *testing.T) {
	t.Parallel()
	if !ufwEnabledFromConfContent("# comment\nENABLED=yes\n") {
		t.Fatalf("ENABLED=yes")
	}
	if ufwEnabledFromConfContent("ENABLED=no\n") {
		t.Fatalf("ENABLED=no")
	}
	if !ufwEnabledFromConfContent("enabled=true\n") {
		t.Fatalf("lowercase key and true")
	}
}
