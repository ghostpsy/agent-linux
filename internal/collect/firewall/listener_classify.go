//go:build linux

package firewall

import (
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"

	"ghostpsy/agent-linux/internal/payload"
)

// ApplyFirewallRuleToListeners sets listener.firewall_rule using iptables INPUT (preferred) or
// nftables filter INPUT hook rules. Uses IPv4 or IPv6 iptables based on the listener bind address.
func ApplyFirewallRuleToListeners(listeners []payload.Listener, fw *payload.Firewall) []payload.Listener {
	if len(listeners) == 0 {
		return listeners
	}
	ipt4Policy, ipt4Lines, ipt4Err := readIptablesInputState(iptables.ProtocolIPv4)
	ipt6Policy, ipt6Lines, ipt6Err := readIptablesInputState(iptables.ProtocolIPv6)
	nftState, nftErr := loadNftInputFilterState()
	out := make([]payload.Listener, len(listeners))
	for i := range listeners {
		out[i] = listeners[i]
		classification := classifyOneListener(
			listeners[i], fw,
			ipt4Policy, ipt4Lines, ipt4Err,
			ipt6Policy, ipt6Lines, ipt6Err,
			nftState, nftErr,
		)
		out[i].FirewallRule = classification.firewallRule
		out[i].LanFirewallRule = classification.lanFirewallRule
		out[i].WanFirewallRule = classification.wanFirewallRule
	}
	return out
}

type listenerClassification struct {
	firewallRule    string
	lanFirewallRule string
	wanFirewallRule string
}

func classifyOneListener(
	l payload.Listener,
	fw *payload.Firewall,
	ipt4Policy string,
	ipt4Lines []string,
	ipt4Err error,
	ipt6Policy string,
	ipt6Lines []string,
	ipt6Err error,
	nft *nftInputState,
	nftErr error,
) listenerClassification {
	port := l.Port
	if port <= 0 || port > 65535 {
		return listenerClassification{
			firewallRule:    payload.FirewallRuleUnknown,
			lanFirewallRule: payload.FirewallRuleUnknown,
			wanFirewallRule: payload.FirewallRuleUnknown,
		}
	}
	bindLoop := listenerBindLoopback(l.Bind)
	v6 := listenerUsesIPv6(l.Bind)
	var iptPol string
	var iptLines []string
	var iptErr error
	if v6 {
		iptPol, iptLines, iptErr = ipt6Policy, ipt6Lines, ipt6Err
	} else {
		iptPol, iptLines, iptErr = ipt4Policy, ipt4Lines, ipt4Err
	}
	if iptErr == nil {
		firewallRule := classifyFromIptablesInputLines(iptPol, iptLines, port, bindLoop)
		lanFirewallRule, wanFirewallRule := classifyFromIptablesInputLinesLanWan(iptPol, iptLines, port, bindLoop)
		return listenerClassification{
			firewallRule:    firewallRule,
			lanFirewallRule: lanFirewallRule,
			wanFirewallRule: wanFirewallRule,
		}
	}
	if nftErr == nil && nft != nil {
		r := classifyFromNFTRules(nft.rules, nft.defaultPolicy, uint16(port), v6)
		return listenerClassification{
			firewallRule:    r,
			lanFirewallRule: r,
			wanFirewallRule: r,
		}
	}
	if fw != nil && fw.Error != "" {
		return listenerClassification{
			firewallRule:    payload.FirewallRuleUnknown,
			lanFirewallRule: payload.FirewallRuleUnknown,
			wanFirewallRule: payload.FirewallRuleUnknown,
		}
	}
	return listenerClassification{
		firewallRule:    payload.FirewallRuleUnknown,
		lanFirewallRule: payload.FirewallRuleUnknown,
		wanFirewallRule: payload.FirewallRuleUnknown,
	}
}

func listenerBindLoopback(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func listenerUsesIPv6(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	if strings.HasPrefix(host, "[") {
		host = strings.Trim(host, "[]")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}
