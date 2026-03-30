//go:build linux

package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// isIptablesParityFilterTable matches iptables -t filter (not nat/mangle/raw, not bridge netdev tables).
func isIptablesParityFilterTable(t *nftables.Table) bool {
	if t == nil || t.Name != "filter" {
		return false
	}
	switch t.Family {
	case nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6:
		return true
	default:
		return false
	}
}

func collectNftablesMetrics() (firewallMetrics, int, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return firewallMetrics{}, 0, err
	}
	defer func() { _ = c.CloseLasting() }()
	chains, err := c.ListChains()
	if err != nil {
		return firewallMetrics{}, 0, err
	}
	var m firewallMetrics
	total := 0
	filterChainCount := 0
	for _, ch := range chains {
		if ch.Table == nil || !isIptablesParityFilterTable(ch.Table) {
			continue
		}
		filterChainCount++
		t := ch.Table
		rules, err := c.GetRules(t, ch)
		if err != nil {
			return firewallMetrics{}, 0, err
		}
		total += len(rules)
		if !m.HasEstablishedRelated {
			m.HasEstablishedRelated = nftRulesMentionCtState(rules)
		}
		if ch.Type == nftables.ChainTypeFilter && ch.Hooknum != nil && ch.Policy != nil {
			if nftables.ChainHookInput != nil && *ch.Hooknum == *nftables.ChainHookInput {
				m.DefaultPolicyIn = nftChainPolicyString(*ch.Policy)
			}
			if nftables.ChainHookOutput != nil && *ch.Hooknum == *nftables.ChainHookOutput {
				m.DefaultPolicyOut = nftChainPolicyString(*ch.Policy)
			}
		}
	}
	m.RuleCount = total
	return m, filterChainCount, nil
}

func nftChainPolicyString(p nftables.ChainPolicy) string {
	if p == nftables.ChainPolicyAccept {
		return "ACCEPT"
	}
	return "DROP"
}

func nftRulesMentionCtState(rules []*nftables.Rule) bool {
	for _, r := range rules {
		for _, e := range r.Exprs {
			ct, ok := e.(*expr.Ct)
			if ok && ct.Key == expr.CtKeySTATE {
				return true
			}
		}
	}
	return false
}
