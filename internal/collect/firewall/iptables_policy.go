//go:build linux

package firewall

import "strings"

// policyFromFilterTableLines returns ACCEPT, DROP, or "" if -P for chain is missing.
func policyFromFilterTableLines(lines []string, chain string) string {
	prefix := "-P " + chain + " "
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return strings.ToUpper(fields[2])
			}
		}
	}
	return ""
}

// filterChainsExcludedFromListenerClassification are not on the path for packets delivered to local sockets.
var filterChainsExcludedFromListenerClassification = map[string]struct{}{
	"OUTPUT":  {},
	"FORWARD": {},
}

// UFW stores allows in these chains; they must be evaluated before Docker/Kubernetes helper chains in our
// linear scan, because iptables -S interleaves chains arbitrarily and a DOCKER-USER rule could match first.
const (
	ufwUserInputChainName  = "ufw-user-input"
	ufw6UserInputChainName = "ufw6-user-input"
)

// filterTableRulesForListenerClassification returns all -A / -I rules except OUTPUT/FORWARD, in an order that
// approximates INPUT traversal: INPUT chain first, then ufw user chains, then every other chain (file order
// within each group).
func filterTableRulesForListenerClassification(lines []string) []string {
	var input, ufw4, ufw6, other []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}
		ch := chainFromAppendInsertLine(line)
		if _, skip := filterChainsExcludedFromListenerClassification[ch]; skip {
			continue
		}
		switch ch {
		case "INPUT":
			input = append(input, line)
		case ufwUserInputChainName:
			ufw4 = append(ufw4, line)
		case ufw6UserInputChainName:
			ufw6 = append(ufw6, line)
		default:
			other = append(other, line)
		}
	}
	out := make([]string, 0, len(input)+len(ufw4)+len(ufw6)+len(other))
	out = append(out, input...)
	out = append(out, ufw4...)
	out = append(out, ufw6...)
	out = append(out, other...)
	return out
}

func chainFromAppendInsertLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	if fields[0] != "-A" && fields[0] != "-I" {
		return ""
	}
	return fields[1]
}

// isFilterTableListenerRuleLine is true for rules considered by classifyFromIptablesInputLines (same filter as extraction).
func isFilterTableListenerRuleLine(line string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
		return false
	}
	ch := chainFromAppendInsertLine(line)
	_, skip := filterChainsExcludedFromListenerClassification[ch]
	return !skip
}
