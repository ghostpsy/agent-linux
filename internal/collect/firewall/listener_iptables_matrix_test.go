//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// Matrix: default INPUT policy × filter rules → classifyFromIptablesInputLines. IPv6 uses ip6tables; IPv4 uses iptables.
// If only one stack is locked down, the same TCP port can classify differently; see listener_classify_test.go.
func TestClassifyFromIptablesInputLinesPolicyRulesMatrix(t *testing.T) {
	t.Parallel()
	const portSSH = 22
	const portHTTP = 80

	tcpAccept22 := []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}
	tcpDrop22 := []string{"-A INPUT -p tcp -m tcp --dport 22 -j DROP"}
	tcpFiltered22 := []string{"-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"}
	tcpJump22 := []string{"-A INPUT -p tcp -m tcp --dport 22 -j ufw-user-input"}
	tcpOtherPort := []string{"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"}
	establishedOnly := []string{"-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"}

	cases := []struct {
		name     string
		policy   string
		lines    []string
		port     int
		bindLoop bool
		want     string
	}{
		{name: "DROP_no_rules_port22_blocked", policy: "DROP", lines: nil, port: portSSH, want: payload.FirewallRuleBlocked},
		{name: "ACCEPT_no_rules_port22_unfiltered", policy: "ACCEPT", lines: nil, port: portSSH, want: payload.FirewallRuleUnfiltered},
		{name: "unknown_no_rules_unknown", policy: payload.FirewallRuleUnknown, lines: nil, port: portSSH, want: payload.FirewallRuleUnknown},

		{name: "DROP_dport22_ACCEPT_unfiltered", policy: "DROP", lines: tcpAccept22, port: portSSH, want: payload.FirewallRuleUnfiltered},
		{name: "ACCEPT_dport22_ACCEPT_unfiltered", policy: "ACCEPT", lines: tcpAccept22, port: portSSH, want: payload.FirewallRuleUnfiltered},

		{name: "DROP_dport22_DROP_blocked", policy: "DROP", lines: tcpDrop22, port: portSSH, want: payload.FirewallRuleBlocked},
		{name: "ACCEPT_dport22_DROP_blocked", policy: "ACCEPT", lines: tcpDrop22, port: portSSH, want: payload.FirewallRuleBlocked},

		{name: "DROP_dport22_saddr_filtered", policy: "DROP", lines: tcpFiltered22, port: portSSH, want: payload.FirewallRuleFiltered},
		{name: "ACCEPT_dport22_saddr_filtered", policy: "ACCEPT", lines: tcpFiltered22, port: portSSH, want: payload.FirewallRuleFiltered},

		{name: "DROP_rule_only_dport80_classify22_blocked", policy: "DROP", lines: tcpOtherPort, port: portSSH, want: payload.FirewallRuleBlocked},
		{name: "ACCEPT_rule_only_dport80_classify22_unfiltered", policy: "ACCEPT", lines: tcpOtherPort, port: portSSH, want: payload.FirewallRuleUnfiltered},

		{name: "DROP_jump_unknown", policy: "DROP", lines: tcpJump22, port: portSSH, want: payload.FirewallRuleUnknown},
		{name: "ACCEPT_jump_unknown", policy: "ACCEPT", lines: tcpJump22, port: portSSH, want: payload.FirewallRuleUnknown},

		{name: "DROP_established_only_new_tcp22_blocked", policy: "DROP", lines: establishedOnly, port: portSSH, want: payload.FirewallRuleBlocked},
		{name: "ACCEPT_established_only_new_tcp22_unfiltered", policy: "ACCEPT", lines: establishedOnly, port: portSSH, want: payload.FirewallRuleUnfiltered},

		{name: "DROP_dport80_rule_classify80_unfiltered", policy: "DROP", lines: tcpOtherPort, port: portHTTP, want: payload.FirewallRuleUnfiltered},
		{name: "ACCEPT_dport80_rule_classify80_unfiltered", policy: "ACCEPT", lines: tcpOtherPort, port: portHTTP, want: payload.FirewallRuleUnfiltered},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyFromIptablesInputLines(tc.policy, tc.lines, tc.port, tc.bindLoop)
			if got != tc.want {
				t.Fatalf("policy=%q lines=%v port=%d bindLoop=%v: got %q want %q",
					tc.policy, tc.lines, tc.port, tc.bindLoop, got, tc.want)
			}
		})
	}
}

func TestClassifyFromIptablesMatrixSnapshotDocumentsExpectedPairs(t *testing.T) {
	t.Parallel()
	diverge := []struct {
		name    string
		acceptW string
		dropW   string
		lines   []string
		port    int
	}{
		{
			name:    "no_rules",
			acceptW: payload.FirewallRuleUnfiltered,
			dropW:   payload.FirewallRuleBlocked,
			lines:   nil,
			port:    22,
		},
		{
			name:    "rule_other_port_classify_ssh",
			acceptW: payload.FirewallRuleUnfiltered,
			dropW:   payload.FirewallRuleBlocked,
			lines:   []string{"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"},
			port:    22,
		},
		{
			name:    "established_only",
			acceptW: payload.FirewallRuleUnfiltered,
			dropW:   payload.FirewallRuleBlocked,
			lines:   []string{"-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"},
			port:    22,
		},
	}
	for _, d := range diverge {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			gotAccept := classifyFromIptablesInputLines("ACCEPT", d.lines, d.port, false)
			gotDrop := classifyFromIptablesInputLines("DROP", d.lines, d.port, false)
			if gotAccept != d.acceptW || gotDrop != d.dropW {
				t.Fatalf("ACCEPT got %q want %q; DROP got %q want %q (lines=%v port=%d)",
					gotAccept, d.acceptW, gotDrop, d.dropW, d.lines, d.port)
			}
			if gotAccept == gotDrop {
				t.Fatalf("expected ACCEPT and DROP to differ for this scenario; both %q", gotAccept)
			}
		})
	}
}

func TestClassifyFromIptablesMatrixPolicyStringsNormalized(t *testing.T) {
	t.Parallel()
	got := classifyFromIptablesInputLines("drop", nil, 22, false)
	if got != payload.FirewallRuleBlocked {
		t.Fatalf("got %q want blocked", got)
	}
	got2 := classifyFromIptablesInputLines("accept", nil, 22, false)
	if got2 != payload.FirewallRuleUnfiltered {
		t.Fatalf("got %q want unfiltered", got2)
	}
}
