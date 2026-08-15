//go:build linux

package firewall

import (
	"context"
	"errors"
	"strings"
)

// errNoRulesetAvailable means we could not read the packet filter at all. It is
// deliberately distinct from "no rules": an empty firewall and an unreadable
// one are different facts, and only one of them is alarming.
var errNoRulesetAvailable = errors.New("firewall: packet filter ruleset could not be read")

func filterChainsIndicateUfwBackend(chainNames []string) bool {
	for _, name := range chainNames {
		if strings.Contains(strings.ToLower(name), "ufw") {
			return true
		}
	}
	return false
}

// filterRuleLinesMentionUfw detects UFW-managed iptables when INPUT jumps to ufw-before-* / ufw-user-*.
// go-iptables ListChains stops at the first non -P/-N line; on Ubuntu 16, -A rules often precede -N ufw-*
// in `iptables -S` order, so chain names alone miss UFW.
func filterRuleLinesMentionUfw(lines []string) bool {
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "ufw") {
			return true
		}
	}
	return false
}

// collectIptablesMetrics derives every firewall number from the ruleset we
// already fetched through privexec.
//
// It used to ask github.com/coreos/go-iptables, which runs the iptables binary
// itself and therefore bypasses privexec: an unprivileged agent got
// "Permission denied (you must be root)" and lost the rule count, both default
// policies and the established/related flag. Parsing the dump we hold removes
// that whole class of problem instead of working around it.
func collectIptablesMetrics(ctx context.Context) (firewallMetrics, int, bool, error) {
	dump, _ := captureRuleset(ctx)
	if len(dump) == 0 {
		return firewallMetrics{}, 0, false, errNoRulesetAvailable
	}

	table := parseIptablesSave(string(dump))

	return firewallMetrics{
		DefaultPolicyIn:       table.Policies["INPUT"],
		DefaultPolicyOut:      table.Policies["OUTPUT"],
		RuleCount:             len(table.Rules),
		HasEstablishedRelated: table.HasEstablishedRelated(),
	}, len(table.Chains), table.MentionsUfw(), nil
}

func iptablesRuleLinesHaveEstablishedRelated(rules []string) bool {
	for _, line := range rules {
		u := strings.ToUpper(line)
		if strings.Contains(u, "ESTABLISHED") || strings.Contains(u, "RELATED") {
			return true
		}
	}
	return false
}
