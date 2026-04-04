//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// IPv6 listeners read ip6tables; IPv4 listeners read iptables. Applying rules to only one stack (e.g. Makefile
// iptables-only) leaves the other stack at default ACCEPT → unfiltered without explicit allow rules.
func TestClassifyOneListenerIPv4VsIPv6PolicyMismatch(t *testing.T) {
	t.Parallel()
	ipt4AllowSSH := []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}
	got4 := classifyOneListener(
		payload.Listener{Bind: "0.0.0.0:25", Port: 25},
		nil,
		"DROP", ipt4AllowSSH, nil,
		"ACCEPT", nil, nil,
		nil, nil,
	)
	if got4.firewallRule != payload.FirewallRuleBlocked {
		t.Fatalf("IPv4 bind with DROP+no rule for 25: got %q want blocked", got4.firewallRule)
	}
	got6 := classifyOneListener(
		payload.Listener{Bind: "[::]:25", Port: 25},
		nil,
		"DROP", ipt4AllowSSH, nil,
		"ACCEPT", nil, nil,
		nil, nil,
	)
	if got6.firewallRule != payload.FirewallRuleUnfiltered {
		t.Fatalf("IPv6 bind with ACCEPT empty rules: got %q want unfiltered", got6.firewallRule)
	}
}

func TestClassifyOneListenerIPv4VsIPv6SamePolicyBlocked(t *testing.T) {
	t.Parallel()
	ipt4AllowSSH := []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}
	ipt6AllowSSH := []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}
	got4 := classifyOneListener(
		payload.Listener{Bind: "0.0.0.0:25", Port: 25},
		nil,
		"DROP", ipt4AllowSSH, nil,
		"DROP", ipt6AllowSSH, nil,
		nil, nil,
	)
	got6 := classifyOneListener(
		payload.Listener{Bind: "[::]:25", Port: 25},
		nil,
		"DROP", ipt4AllowSSH, nil,
		"DROP", ipt6AllowSSH, nil,
		nil, nil,
	)
	if got4.firewallRule != payload.FirewallRuleBlocked || got6.firewallRule != payload.FirewallRuleBlocked {
		t.Fatalf("both stacks DROP+no rule for 25: IPv4 got %q IPv6 got %q want blocked", got4.firewallRule, got6.firewallRule)
	}
}
