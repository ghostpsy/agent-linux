//go:build linux

package firewall

import (
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

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

func iptablesExecutablePath() string {
	if p, err := exec.LookPath("iptables"); err == nil {
		return p
	}
	for _, p := range []string{"/sbin/iptables", "/usr/sbin/iptables"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "iptables"
}

// filterTableFullSaveOutputMentionsUfw reads the entire filter table (`iptables -t filter -S`).
// go-iptables ListChains is incomplete when -A lines precede -N lines; per-chain List can miss UFW on some hosts.
func filterTableFullSaveOutputMentionsUfw() bool {
	out, err := exec.Command(iptablesExecutablePath(), "-t", "filter", "-S").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "ufw")
}

func collectIptablesMetrics() (firewallMetrics, int, bool, error) {
	ipt, err := iptables.New()
	if err != nil {
		return firewallMetrics{}, 0, false, err
	}
	in, out, err := filterDefaultPoliciesFromIptables(ipt)
	if err != nil {
		return firewallMetrics{}, 0, false, err
	}
	chains, err := ipt.ListChains("filter")
	if err != nil {
		return firewallMetrics{}, 0, false, err
	}
	ufwBackend := filterChainsIndicateUfwBackend(chains)
	if !ufwBackend {
		inputLines, errIn := ipt.List("filter", "INPUT")
		if errIn == nil && filterRuleLinesMentionUfw(inputLines) {
			ufwBackend = true
		}
	}
	if !ufwBackend && filterTableFullSaveOutputMentionsUfw() {
		ufwBackend = true
	}
	n := 0
	hasEst := false
	for _, chain := range chains {
		rules, err := ipt.List("filter", chain)
		if err != nil {
			return firewallMetrics{}, 0, false, err
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
	}, len(chains), ufwBackend, nil
}

// filterDefaultPoliciesFromIptables reads default policies from a full filter table dump when possible.
// Per-chain List output can omit -P lines on some iptables-nft builds.
func filterDefaultPoliciesFromIptables(ipt *iptables.IPTables) (in, out string, err error) {
	inLines, errIn := ipt.List("filter", "INPUT")
	if errIn != nil {
		return "", "", errIn
	}
	outLines, errOut := ipt.List("filter", "OUTPUT")
	if errOut != nil {
		return "", "", errOut
	}
	inPol := policyFromFilterTableLines(inLines, "INPUT")
	outPol := policyFromFilterTableLines(outLines, "OUTPUT")
	if inPol == "" {
		inPol = policyFromIptablesSOutputLines(inLines, "INPUT")
	}
	if outPol == "" {
		outPol = policyFromIptablesSOutputLines(outLines, "OUTPUT")
	}
	return inPol, outPol, nil
}

func policyFromIptablesSOutputLines(lines []string, chainName string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "-P" && fields[1] == chainName {
			return strings.ToUpper(fields[2])
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
