//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	maxUfwVerboseLines   = 24
	maxRulesetExcerpt    = 2048
	rulesetCaptureMillis = 3500
)

// enrichFirewallDetails adds firewalld/ufw hints and a bounded ruleset hash + excerpt (best-effort).
func enrichFirewallDetails(fw *payload.Firewall) {
	if fw == nil {
		return
	}
	fillFirewalldHints(fw)
	fillUfwVerbose(fw)
	fillBackendRulesetFingerprint(fw)
}

func fillFirewalldHints(fw *payload.Firewall) {
	if !commandOnPath("firewall-cmd") {
		return
	}
	zOut, err := exec.Command("firewall-cmd", "--get-default-zone").Output()
	if err != nil {
		return
	}
	zone := strings.TrimSpace(string(zOut))
	if zone == "" {
		return
	}
	fw.FirewalldDefaultZone = shared.TruncateRunes(zone, 64)
	tOut, err := exec.Command("firewall-cmd", "--get-zone-target", "--zone", zone).Output()
	if err == nil {
		fw.FirewalldZoneTarget = shared.TruncateRunes(strings.TrimSpace(string(tOut)), 64)
	}
}

func fillUfwVerbose(fw *payload.Firewall) {
	path := ufwExecutablePath()
	if path == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "status", "verbose")
	b, err := cmd.Output()
	if err != nil {
		return
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		line = redactFirewallTelemetryLine(line)
		lines = append(lines, shared.TruncateRunes(line, 256))
		if len(lines) >= maxUfwVerboseLines {
			break
		}
	}
	fw.UfwStatusVerboseSample = lines
}

func fillBackendRulesetFingerprint(fw *payload.Firewall) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rulesetCaptureMillis)*time.Millisecond)
	defer cancel()
	raw, _ := captureRuleset(ctx)
	if len(raw) == 0 {
		return
	}
	redacted := redactRulesetDumpForIngest(string(raw))
	sum := sha256.Sum256([]byte(redacted))
	fw.BackendRulesetSha256Hex = hex.EncodeToString(sum[:])
	fw.BackendRulesetExcerpt = shared.TruncateRunes(redacted, maxRulesetExcerpt)
}

func captureRuleset(ctx context.Context) ([]byte, string) {
	cmd := exec.CommandContext(ctx, "iptables-save")
	b, err := cmd.Output()
	if err == nil && len(b) > 0 {
		return b, "iptables-save"
	}
	cmd = exec.CommandContext(ctx, "nft", "list", "ruleset")
	b, err = cmd.Output()
	if err == nil && len(b) > 0 {
		return b, "nft"
	}
	return nil, ""
}
