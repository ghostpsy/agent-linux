//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestClassifyFromIptablesInputLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		policy   string
		lines    []string
		port     int
		bindLoop bool
		want     string
	}{
		{
			name:     "default drop no port rule",
			policy:   "DROP",
			lines:    nil,
			port:     443,
			bindLoop: false,
			want:     payload.FirewallRuleBlocked,
		},
		{
			name:     "default accept no rules",
			policy:   "ACCEPT",
			lines:    nil,
			port:     80,
			bindLoop: false,
			want:     payload.FirewallRuleUnfiltered,
		},
		{
			name:   "tcp dport accept",
			policy: "DROP",
			lines: []string{
				"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleUnfiltered,
		},
		{
			name:   "tcp dport drop",
			policy: "ACCEPT",
			lines: []string{
				"-A INPUT -p tcp -m tcp --dport 22 -j DROP",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleBlocked,
		},
		{
			name:   "restricted source accept",
			policy: "DROP",
			lines: []string{
				"-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleFiltered,
		},
		{
			name:   "lo accept loopback listener",
			policy: "DROP",
			lines: []string{
				"-A INPUT -i lo -j ACCEPT",
			},
			port:     5432,
			bindLoop: true,
			want:     payload.FirewallRuleUnfiltered,
		},
		{
			name:   "lo accept not loopback bind",
			policy: "DROP",
			lines: []string{
				"-A INPUT -i lo -j ACCEPT",
				"-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
			},
			port:     443,
			bindLoop: false,
			want:     payload.FirewallRuleUnfiltered,
		},
		{
			name:   "jump to user chain",
			policy: "ACCEPT",
			lines: []string{
				"-A INPUT -p tcp -m tcp --dport 22 -j f2b-sshd",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleUnknown,
		},
		{
			name:     "policy unknown no match",
			policy:   payload.FirewallRuleUnknown,
			lines:    nil,
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleUnknown,
		},
		{
			name:   "ufw_user_input_tcp_dport_accept",
			policy: "DROP",
			lines: []string{
				"-A INPUT -j ufw-before-input",
				"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleUnfiltered,
		},
		{
			name:   "ufw6_user_input_tcp_dport_accept",
			policy: "DROP",
			lines: []string{
				"-A INPUT -j ufw6-before-input",
				"-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
			},
			port:     22,
			bindLoop: false,
			want:     payload.FirewallRuleUnfiltered,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyFromIptablesInputLines(tc.policy, tc.lines, tc.port, tc.bindLoop)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
