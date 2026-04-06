//go:build linux

package firewall

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// readIptablesInputState returns INPUT default policy and filter-table rules used for listener classification
// (see filterTableRulesForListenerClassification layer order). Rules are built from per-chain List via go-iptables.
func readIptablesInputState(proto iptables.Protocol) (policy string, inputRules []string, err error) {
	ipt, err := iptables.New(iptables.IPFamily(proto))
	if err != nil {
		return "", nil, err
	}
	chains, err := ipt.ListChains("filter")
	if err != nil {
		return "", nil, err
	}
	var input, ufw4, ufw6, other []string
	for _, ch := range chains {
		if shouldSkipFilterChainForHostListenerClassification(ch) {
			continue
		}
		rules, errL := ipt.List("filter", ch)
		if errL != nil {
			continue
		}
		switch ch {
		case "INPUT":
			input = append(input, rules...)
		case ufwUserInputChainName:
			ufw4 = append(ufw4, rules...)
		case ufw6UserInputChainName:
			ufw6 = append(ufw6, rules...)
		default:
			other = append(other, rules...)
		}
	}
	inputRules = make([]string, 0, len(input)+len(ufw4)+len(ufw6)+len(other))
	inputRules = append(inputRules, input...)
	inputRules = append(inputRules, ufw4...)
	inputRules = append(inputRules, ufw6...)
	inputRules = append(inputRules, other...)
	policy = policyFromFilterTableLines(input, "INPUT")
	if policy == "" {
		policy = payload.FirewallRuleUnknown
	}
	return policy, inputRules, nil
}

// classifyFromIptablesInputLines evaluates filter INPUT rules in order for a new TCP connection to port.
// defaultPolicy is ACCEPT, DROP, or payload.FirewallRuleUnknown when policy could not be read.
func classifyFromIptablesInputLines(defaultPolicy string, lines []string, port int, bindLoopback bool) string {
	policy := strings.TrimSpace(defaultPolicy)
	if policy == "" {
		policy = payload.FirewallRuleUnknown
	}
	if policy != payload.FirewallRuleUnknown {
		policy = strings.ToUpper(policy)
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "-P INPUT") {
			continue
		}
		if !isFilterTableListenerRuleLine(line) {
			continue
		}
		if !iptablesRuleMatchesNewTCPToPort(line, port, bindLoopback) {
			continue
		}
		target := iptablesJumpTarget(line)
		switch target {
		case "ACCEPT":
			if iptablesSourceRestricted(line) {
				return payload.FirewallRuleFiltered
			}
			return payload.FirewallRuleUnfiltered
		case "DROP", "REJECT":
			return payload.FirewallRuleBlocked
		case "RETURN", "LOG":
			continue
		default:
			if target != "" {
				return payload.FirewallRuleUnknown
			}
		}
	}
	if policy == "DROP" {
		return payload.FirewallRuleBlocked
	}
	if policy == payload.FirewallRuleUnknown {
		return payload.FirewallRuleUnknown
	}
	return payload.FirewallRuleUnfiltered
}

type trafficSourceScope int

const (
	sourceScopeLAN trafficSourceScope = iota
	sourceScopeWAN
)

var (
	lanIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	lanIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("fc00::/7"),
	}
	wanIPv4Reps = []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
	}
	wanIPv6Reps = []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
)

func classifyFromIptablesInputLinesLanWan(defaultPolicy string, lines []string, port int, bindLoopback bool) (lanRule string, wanRule string) {
	policy := strings.TrimSpace(defaultPolicy)
	if policy == "" {
		policy = payload.FirewallRuleUnknown
	}
	policy = strings.ToUpper(policy)

	var defaultRule string
	switch policy {
	case payload.FirewallRuleUnknown:
		defaultRule = payload.FirewallRuleUnknown
	case "DROP":
		defaultRule = payload.FirewallRuleBlocked
	default:
		defaultRule = payload.FirewallRuleUnfiltered
	}

	return classifyFromIptablesInputLinesSourceScope(lines, port, bindLoopback, sourceScopeLAN, defaultRule),
		classifyFromIptablesInputLinesSourceScope(lines, port, bindLoopback, sourceScopeWAN, defaultRule)
}

func classifyFromIptablesInputLinesSourceScope(lines []string, port int, bindLoopback bool, scope trafficSourceScope, defaultRule string) string {
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "-P INPUT") {
			continue
		}
		if !isFilterTableListenerRuleLine(line) {
			continue
		}
		if !iptablesRuleMatchesNewTCPToPort(line, port, bindLoopback) {
			continue
		}
		if !iptablesRuleMatchesSourceScope(line, scope) {
			continue
		}

		target := iptablesJumpTarget(line)
		switch target {
		case "ACCEPT":
			hasSource, sourceIsAny := iptablesRuleHasSourceSelector(line)
			if !hasSource || sourceIsAny {
				return payload.FirewallRuleUnfiltered
			}
			return payload.FirewallRuleFiltered
		case "DROP", "REJECT":
			return payload.FirewallRuleBlocked
		case "RETURN", "LOG":
			continue
		default:
			if target != "" {
				return payload.FirewallRuleUnknown
			}
		}
	}
	return defaultRule
}

func iptablesRuleHasSourceSelector(line string) (hasSource bool, sourceIsAny bool) {
	// Source selector is considered "any" when it matches 0.0.0.0/0 or ::/0.
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] != "-s" && fields[i] != "--source" {
			continue
		}
		src := fields[i+1]
		prefix, err := netip.ParsePrefix(src)
		if err == nil {
			return true, prefix.Bits() == 0
		}
		if _, err2 := netip.ParseAddr(src); err2 == nil {
			return true, false
		}
		return true, false
	}
	return false, false
}

func iptablesRuleMatchesSourceScope(line string, scope trafficSourceScope) bool {
	fields := strings.Fields(line)
	var src string
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] != "-s" && fields[i] != "--source" {
			continue
		}
		src = fields[i+1]
		break
	}
	if src == "" {
		return true
	}
	prefix, err := netip.ParsePrefix(src)
	if err != nil {
		addr, err2 := netip.ParseAddr(src)
		if err2 != nil {
			return false
		}
		bits := addr.BitLen()
		prefix = netip.PrefixFrom(addr, bits)
	}
	if prefix.Bits() == 0 {
		return true
	}

	if scope == sourceScopeLAN {
		return iptablesSourceOverlapsLAN(prefix)
	}
	return iptablesSourceOverlapsWAN(prefix)
}

func iptablesSourceOverlapsLAN(srcPrefix netip.Prefix) bool {
	if srcPrefix.Addr().Is4() {
		for _, lan := range lanIPv4Prefixes {
			if prefixesOverlap(srcPrefix, lan) {
				return true
			}
		}
		return false
	}
	for _, lan := range lanIPv6Prefixes {
		if prefixesOverlap(srcPrefix, lan) {
			return true
		}
	}
	return false
}

func iptablesSourceOverlapsWAN(srcPrefix netip.Prefix) bool {
	if srcPrefix.Addr().Is4() {
		for _, rep := range wanIPv4Reps {
			if srcPrefix.Contains(rep) {
				return true
			}
		}
		return false
	}
	for _, rep := range wanIPv6Reps {
		if srcPrefix.Contains(rep) {
			return true
		}
	}
	return false
}

func prefixesOverlap(a, b netip.Prefix) bool {
	am := a.Masked()
	bm := b.Masked()
	return am.Contains(bm.Addr()) || bm.Contains(am.Addr())
}

func iptablesJumpTarget(line string) string {
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-j" {
			return strings.ToUpper(fields[i+1])
		}
	}
	return ""
}

func iptablesSourceRestricted(line string) bool {
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] != "-s" {
			continue
		}
		cidr := fields[i+1]
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return false
		}
		return true
	}
	return false
}

func iptablesRuleMatchesNewTCPToPort(line string, port int, bindLoopback bool) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "-p udp") || strings.Contains(lower, "-p icmp") || strings.Contains(lower, "-p icmpv6") {
		return false
	}
	if strings.Contains(lower, "-m state") || strings.Contains(lower, "--ctstate") {
		if strings.Contains(lower, "established") || strings.Contains(lower, "related") {
			if !containsDportSpec(line) {
				return false
			}
		}
	}
	if hasIFaceLo(line) {
		if !bindLoopback {
			return false
		}
	} else if hasIFaceNonLo(line) {
		if bindLoopback {
			return false
		}
	}
	if strings.Contains(lower, "-p udp") {
		return false
	}
	if iptablesMatchesTCPPort(line, port) {
		return true
	}
	if iptablesGenericFilterRule(line) {
		return true
	}
	return false
}

func hasIFaceLo(line string) bool {
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-i" && fields[i+1] == "lo" {
			return true
		}
	}
	return false
}

func hasIFaceNonLo(line string) bool {
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-i" && fields[i+1] != "lo" {
			return true
		}
	}
	return false
}

func containsDportSpec(line string) bool {
	return strings.Contains(line, "--dport") || strings.Contains(line, "--dports")
}

func iptablesMatchesTCPPort(line string, port int) bool {
	if strings.Contains(strings.ToLower(line), "-p udp") {
		return false
	}
	if !mentionsTCP(line) && containsDportSpec(line) {
		return portInDportSpecs(line, port)
	}
	if !mentionsTCP(line) && !containsDportSpec(line) {
		return false
	}
	if !containsDportSpec(line) {
		return mentionsTCP(line)
	}
	return portInDportSpecs(line, port)
}

func mentionsTCP(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "-p tcp") || strings.Contains(lower, "-p 6") || strings.Contains(lower, "-m tcp") || strings.Contains(lower, "-m multiport")
}

func portInDportSpecs(line string, want int) bool {
	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		if fields[i] != "--dport" && fields[i] != "--dports" {
			continue
		}
		if i+1 >= len(fields) {
			continue
		}
		val := fields[i+1]
		for _, part := range strings.Split(val, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, ":") {
				lo, hi, ok := parsePortRange(part)
				if ok && want >= lo && want <= hi {
					return true
				}
				continue
			}
			p, err := strconv.Atoi(part)
			if err == nil && p == want {
				return true
			}
		}
	}
	return false
}

func parsePortRange(s string) (lo, hi int, ok bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e1 != nil || e2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

func iptablesGenericFilterRule(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "-p udp") || strings.Contains(lower, "-p icmp") || strings.Contains(lower, "-p icmpv6") {
		return false
	}
	if mentionsTCP(line) || containsDportSpec(line) {
		return false
	}
	t := iptablesJumpTarget(line)
	return t == "ACCEPT" || t == "DROP" || t == "REJECT"
}
