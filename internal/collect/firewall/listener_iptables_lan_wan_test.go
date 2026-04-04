//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestClassifyFromIptablesInputLinesLanWan(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		policy   string
		lines    []string
		port     int
		bindLoop bool
		wantLan  string
		wantWan  string
	}{
		{
			name:     "drop_no_rules",
			policy:   "DROP",
			lines:    nil,
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleBlocked,
			wantWan:  payload.FirewallRuleBlocked,
		},
		{
			name:     "drop_accept_any_source",
			policy:   "DROP",
			lines:    []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"},
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleUnfiltered,
			wantWan:  payload.FirewallRuleUnfiltered,
		},
		{
			name:     "drop_accept_lan_source",
			policy:   "DROP",
			lines:    []string{"-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"},
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleFiltered,
			wantWan:  payload.FirewallRuleBlocked,
		},
		{
			name:     "drop_accept_wan_source_subset",
			policy:   "DROP",
			lines:    []string{"-A INPUT -p tcp -m tcp --dport 22 -s 8.8.8.0/24 -j ACCEPT"},
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleBlocked,
			wantWan:  payload.FirewallRuleFiltered,
		},
		{
			name:     "accept_default_with_lan_only_rule",
			policy:   "ACCEPT",
			lines:    []string{"-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"},
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleFiltered,
			wantWan:  payload.FirewallRuleUnfiltered,
		},
		{
			name:     "drop_accept_ula_source_v6",
			policy:   "DROP",
			lines:    []string{"-A INPUT -p tcp -m tcp --dport 22 -s fc00::/7 -j ACCEPT"},
			port:     22,
			bindLoop: false,
			wantLan:  payload.FirewallRuleFiltered,
			wantWan:  payload.FirewallRuleBlocked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotLan, gotWan := classifyFromIptablesInputLinesLanWan(tc.policy, tc.lines, tc.port, tc.bindLoop)
			if gotLan != tc.wantLan || gotWan != tc.wantWan {
				t.Fatalf("got (lan=%q wan=%q) want (lan=%q wan=%q)", gotLan, gotWan, tc.wantLan, tc.wantWan)
			}
		})
	}
}
