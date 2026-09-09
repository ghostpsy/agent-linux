//go:build linux

package firewall

import (
	"context"
	"github.com/ghostpsy/agent-linux/internal/payload"
	"strings"
)

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
func CollectFirewall(ctx context.Context) *payload.Firewall {
	fw := &payload.Firewall{}
	defer func() {
		enrichFirewallDetails(ctx, fw)
		applyFirewallActive(fw)
	}()
	if firewalldRunning(ctx) {
		fw.Family = fwFirewalld
		if m, _, _, err := collectIptablesMetrics(ctx); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		if m, _, err := collectNftablesMetrics(ctx); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		fw.Error = collectionNote("Firewall metrics could not be read (nftables and iptables).")
		return fw
	}
	if ufwStatusActive(ctx) || ufwPersistedEnabled() {
		fw.Family = fwUfw
		if m, _, _, err := collectIptablesMetrics(ctx); err == nil {
			applyMetrics(fw, m)
			return fw
		}
		fw.Error = collectionNote("Firewall metrics could not be read from iptables.")
		return fw
	}
	// Prefer iptables when the CLI works: metrics match `iptables` / iptables-nft; pure nft-only hosts still use netlink below.
	mIpt, iptChainCount, iptablesIndicatesUfwBackend, errIpt := collectIptablesMetrics(ctx)
	if errIpt == nil && (iptChainCount > 0 || mIpt.RuleCount > 0) {
		if iptablesIndicatesUfwBackend {
			fw.Family = fwUfw
		} else {
			fw.Family = fwIptables
		}
		applyMetrics(fw, mIpt)
		return fw
	}
	mNft, nftChainCount, errNft := collectNftablesMetrics(ctx)
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

// applyFirewallActive says whether this machine is really filtering traffic.
//
// Only ufw or firewalld count — raw iptables or nftables rules alone are not a
// host firewall.
//
// For ufw the answer comes from `ufw status`, read with privilege a moment
// earlier, and not from the family. The family is set when `ufw status` says
// active *or* /etc/ufw/ufw.conf says ENABLED=yes, and that "or" was reporting a
// firewall as active on a machine filtering nothing.
//
// It has to be that "or", though. Unprivileged `ufw status` answers "ERROR: You
// need to be root", so without the config there would be no answer at all on a
// machine where the privileged read fails. Hence: believe the status when we
// have it, fall back to the config when we do not, and record which.
func applyFirewallActive(fw *payload.Firewall) {
	applyFirewallActiveFrom(fw, ufwPersistedEnabled())
}

// applyFirewallActiveFrom is the decision on its own, so a test can say what the
// configuration holds instead of depending on the /etc/ufw/ufw.conf of whichever
// machine happens to be running the tests.
func applyFirewallActiveFrom(fw *payload.Firewall, persisted bool) {
	if fw == nil {
		return
	}
	if fw.Family == fwUfw {
		fw.ConfiguredOn = &persisted
		switch ufwStatusFromVerbose(fw.UfwStatusVerboseSample) {
		case ufwStatusActiveText:
			fw.Active = true
		case ufwStatusInactiveText:
			fw.Active = false
		default:
			// Nothing readable said so. The configuration is all there is.
			fw.Active = persisted
		}
		return
	}
	switch fw.Family {
	case fwFirewalld:
		fw.Active = true
	default:
		fw.Active = false
	}
}

const (
	ufwStatusActiveText   = "active"
	ufwStatusInactiveText = "inactive"
	ufwStatusUnknownText  = "unknown"
)

// ufwStatusFromVerbose reads the answer out of `ufw status verbose` output.
//
// "Status: inactive" has to be looked for before "active", because it contains
// it. Matching "active" first would call every switched-off firewall active,
// which is the mistake this whole function exists to stop making.
func ufwStatusFromVerbose(lines []string) string {
	for _, line := range lines {
		low := strings.ToLower(line)
		if !strings.Contains(low, "status:") {
			continue
		}
		if strings.Contains(low, ufwStatusInactiveText) {
			return ufwStatusInactiveText
		}
		if strings.Contains(low, ufwStatusActiveText) {
			return ufwStatusActiveText
		}
	}
	return ufwStatusUnknownText
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
