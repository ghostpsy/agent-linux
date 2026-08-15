//go:build linux

package firewall

import "testing"

func TestFilterChainsIndicateUfwBackend(t *testing.T) {
	if !filterChainsIndicateUfwBackend([]string{"INPUT", "ufw-user-input", "FORWARD"}) {
		t.Fatalf("ufw-user-input must imply ufw backend")
	}
	if !filterChainsIndicateUfwBackend([]string{"ufw6-user-input"}) {
		t.Fatalf("ufw6 chains must imply ufw backend")
	}
	if filterChainsIndicateUfwBackend([]string{"INPUT", "DOCKER", "DOCKER-USER"}) {
		t.Fatalf("docker-only chains must not imply ufw")
	}
}

func TestFilterRuleLinesMentionUfw(t *testing.T) {
	lines := []string{"-P INPUT DROP", "-A INPUT -j ufw-before-input"}
	if !filterRuleLinesMentionUfw(lines) {
		t.Fatalf("INPUT jump to ufw-before-input must imply ufw backend")
	}
	if filterRuleLinesMentionUfw([]string{"-P INPUT ACCEPT", "-A INPUT -i lo -j ACCEPT"}) {
		t.Fatalf("rules without ufw must not imply ufw backend")
	}
}
