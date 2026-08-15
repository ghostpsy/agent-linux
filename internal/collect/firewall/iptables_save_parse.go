//go:build linux

package firewall

import "strings"

// filterTable is what a single `iptables-save` filter table tells us.
//
// It exists because the go-iptables library runs the iptables binary itself,
// which means it bypasses privexec and cannot be granted through sudoers. An
// unprivileged agent got "Permission denied (you must be root)" and lost four
// of the eight firewall fields. We already fetch the whole ruleset through
// sudo, so every number below can be derived from what we hold rather than
// asking a library to fetch it a second time, without privilege.
type filterTable struct {
	// Policies holds built-in chains only. A user-defined chain has "-" where
	// a built-in has its policy, and reporting that as a default policy would
	// be wrong.
	Policies map[string]string
	Chains   []string
	Rules    []string
}

func parseIptablesSave(dump string) filterTable {
	table := filterTable{Policies: map[string]string{}}

	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, ":"):
			name, policy := chainDeclaration(line)
			if name == "" {
				continue
			}
			table.Chains = append(table.Chains, name)
			if policy != "-" {
				table.Policies[name] = policy
			}
		case strings.HasPrefix(line, "-A "):
			table.Rules = append(table.Rules, line)
		}
	}

	return table
}

// chainDeclaration reads a ":NAME POLICY [packets:bytes]" line.
func chainDeclaration(line string) (name, policy string) {
	fields := strings.Fields(strings.TrimPrefix(line, ":"))
	if len(fields) < 2 {
		return "", ""
	}
	return fields[0], fields[1]
}

// HasEstablishedRelated reports whether the table lets replies back in. Without
// it a restrictive INPUT policy usually breaks the machine, so its absence is
// worth reporting rather than assuming.
func (t filterTable) HasEstablishedRelated() bool {
	for _, rule := range t.Rules {
		if iptablesRuleLinesHaveEstablishedRelated([]string{rule}) {
			return true
		}
	}
	return false
}

// MentionsUfw reports whether ufw manages this table. Chain names alone are not
// enough: on some hosts the -A rules referencing ufw chains appear before the
// chains are declared, so the rules have to be read too.
func (t filterTable) MentionsUfw() bool {
	for _, name := range t.Chains {
		if strings.Contains(strings.ToLower(name), "ufw") {
			return true
		}
	}
	return filterRuleLinesMentionUfw(t.Rules)
}
