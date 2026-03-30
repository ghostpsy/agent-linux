//go:build linux

package firewall

import "testing"

func TestCountIptablesFilterRuleLinesIgnoresPolicyOnlyLines(t *testing.T) {
	lines := []string{"-P INPUT ACCEPT"}
	if countIptablesFilterRuleLines(lines) != 0 {
		t.Fatalf("policy line must not count as a rule")
	}
	lines2 := []string{"-P INPUT ACCEPT", "-A INPUT -i lo -j ACCEPT"}
	if countIptablesFilterRuleLines(lines2) != 1 {
		t.Fatalf("expected 1 rule")
	}
}

func TestPolicyFromIptablesSOutputLines(t *testing.T) {
	if policyFromIptablesSOutputLines([]string{"-P INPUT DROP", "-A INPUT -j ACCEPT"}, "INPUT") != "DROP" {
		t.Fatalf("INPUT policy")
	}
	if policyFromIptablesSOutputLines([]string{"-P OUTPUT ACCEPT"}, "OUTPUT") != "ACCEPT" {
		t.Fatalf("OUTPUT policy")
	}
}
