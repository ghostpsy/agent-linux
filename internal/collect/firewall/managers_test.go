//go:build linux

package firewall

import "testing"

func TestCollectFirewallManagersShape(t *testing.T) {
	t.Parallel()
	m := collectFirewallManagers()
	if len(m) != 2 {
		t.Fatalf("expected 2 managers, got %d", len(m))
	}
	if m[0].Name != "firewalld" || m[1].Name != "ufw" {
		t.Fatalf("unexpected order: %#v", m)
	}
}
