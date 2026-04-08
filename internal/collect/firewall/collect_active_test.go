//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestApplyFirewallActive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		family string
		want   bool
	}{
		{fwUfw, true},
		{fwFirewalld, true},
		{fwIptables, false},
		{fwNftables, false},
		{fwNoneDetected, false},
	}
	for _, tc := range cases {
		fw := &payload.Firewall{Family: tc.family}
		applyFirewallActive(fw)
		if fw.Active != tc.want {
			t.Fatalf("family %q: active=%v, want %v", tc.family, fw.Active, tc.want)
		}
	}
	applyFirewallActive(nil)
}
