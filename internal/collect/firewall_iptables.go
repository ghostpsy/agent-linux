//go:build linux

package collect

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

func collectIptablesMetrics() (firewallMetrics, int, error) {
	ipt, err := iptables.New()
	if err != nil {
		return firewallMetrics{}, 0, err
	}
	in, out, err := filterDefaultPoliciesFromIptables(ipt)
	if err != nil {
		return firewallMetrics{}, 0, err
	}
	chains, err := ipt.ListChains("filter")
	if err != nil {
		return firewallMetrics{}, 0, err
	}
	n := 0
	hasEst := false
	for _, chain := range chains {
		rules, err := ipt.List("filter", chain)
		if err != nil {
			return firewallMetrics{}, 0, err
		}
		n += countIptablesFilterRuleLines(rules)
		if !hasEst {
			hasEst = iptablesRuleLinesHaveEstablishedRelated(rules)
		}
	}
	return firewallMetrics{
		DefaultPolicyIn:       in,
		DefaultPolicyOut:      out,
		RuleCount:             n,
		HasEstablishedRelated: hasEst,
	}, len(chains), nil
}

// filterDefaultPoliciesFromIptables reads default policies from per-chain List output (iptables -S <chain>).
// go-iptables does not expose GetPolicy; List includes -P lines for that chain.
func filterDefaultPoliciesFromIptables(ipt *iptables.IPTables) (in, out string, err error) {
	inLines, err := ipt.List("filter", "INPUT")
	if err != nil {
		return "", "", err
	}
	outLines, err := ipt.List("filter", "OUTPUT")
	if err != nil {
		return "", "", err
	}
	return policyFromIptablesSOutputLines(inLines, "INPUT"), policyFromIptablesSOutputLines(outLines, "OUTPUT"), nil
}

func policyFromIptablesSOutputLines(lines []string, chainName string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "-P" && fields[1] == chainName {
			return fields[2]
		}
	}
	return ""
}

// countIptablesFilterRuleLines counts real rules from iptables -S output.
// Per-chain -S can include a -P policy line (not a rule); go-iptables List returns it as one line per chain.
func countIptablesFilterRuleLines(lines []string) int {
	n := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A") || strings.HasPrefix(line, "-I") {
			n++
		}
	}
	return n
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
