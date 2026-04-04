//go:build linux

package firewall

import "ghostpsy/agent-linux/internal/payload"

const collectionNoInfoPrefix = "No information extracted."

func collectionNote(detail string) string {
	if len(detail) > 400 {
		detail = detail[:400]
	}
	return collectionNoInfoPrefix + " " + detail
}

const (
	fwIptables     = "iptables"
	fwNftables     = "nftables"
	fwUfw          = "ufw"
	fwFirewalld    = "firewalld"
	fwNoneDetected = "none_detected"
)

type firewallMetrics struct {
	DefaultPolicyIn       string
	DefaultPolicyOut      string
	RuleCount             int
	HasEstablishedRelated bool
}

// CollectFirewall detects iptables / nftables / ufw / firewalld and fills metrics via netlink (nftables) or go-iptables.
// There is no fallback to parsing iptables-save snapshots for these metrics.
func CollectFirewall() *payload.Firewall {
	fw := &payload.Firewall{Managers: collectFirewallManagers()}
	if firewalldRunning() {
		fw.Family = fwFirewalld
		if m, _, _, err := collectIptablesMetrics(); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		if m, _, err := collectNftablesMetrics(); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		fw.Error = collectionNote("Firewall metrics could not be read (nftables and iptables).")
		return fw
	}
	if ufwStatusActive() || ufwPersistedEnabled() {
		fw.Family = fwUfw
		if m, _, _, err := collectIptablesMetrics(); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		fw.Error = collectionNote("Firewall metrics could not be read from iptables.")
		return fw
	}
	// Prefer iptables when the CLI works: metrics match `iptables` / iptables-nft; pure nft-only hosts still use netlink below.
	mIpt, iptChainCount, iptablesIndicatesUfwBackend, errIpt := collectIptablesMetrics()
	if errIpt == nil && (iptChainCount > 0 || mIpt.RuleCount > 0) {
		if iptablesIndicatesUfwBackend {
			fw.Family = fwUfw
		} else {
			fw.Family = fwIptables
		}
		applyMetrics(fw, mIpt)
		return fw
	}
	mNft, nftChainCount, errNft := collectNftablesMetrics()
	if errNft == nil && (nftChainCount > 0 || mNft.RuleCount > 0) {
		fw.Family = fwNftables
		applyMetrics(fw, mNft)
		return fw
	}
	fw.Family = fwNoneDetected
	if errNft != nil && errIpt != nil {
		fw.Error = collectionNote("Firewall metrics could not be read.")
	}
	return fw
}

func applyMetrics(fw *payload.Firewall, m firewallMetrics) {
	if m.DefaultPolicyIn != "" {
		fw.DefaultPolicyIn = m.DefaultPolicyIn
	}
	if m.DefaultPolicyOut != "" {
		fw.DefaultPolicyOut = m.DefaultPolicyOut
	}
	rc := m.RuleCount
	fw.RuleCount = &rc
	est := m.HasEstablishedRelated
	fw.HasEstablishedRelated = &est
}
