//go:build linux

package firewall

import (
	"context"
	"testing"
)

// Migrated to privexec: the ruleset dump is the single biggest thing lost when
// the agent is not root (76% of this section, measured on debian-13), so it
// must go through the declared-command path that sudo actually grants.
func TestCaptureRulesetUsesDeclaredCommands(t *testing.T) {
	raw, backend := captureRuleset(context.Background())

	// On a host with neither backend installed, both are empty and that is a
	// correct answer. What must never happen is a backend name with no data.
	if backend != "" && len(raw) == 0 {
		t.Fatalf("reported backend %q with no ruleset data", backend)
	}
	if backend != "" && backend != "iptables-save" && backend != "nft" {
		t.Fatalf("unexpected backend name %q", backend)
	}
}
