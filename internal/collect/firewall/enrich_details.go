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

const firewalldHintsCmdTimeout = 5 * time.Second

// enrichFirewallDetails adds firewalld/ufw hints and a bounded ruleset hash + excerpt (best-effort).
func enrichFirewallDetails(ctx context.Context, fw *payload.Firewall) {
	if fw == nil {
		return
	}
	fillFirewalldHints(ctx, fw)
	fillUfwVerbose(ctx, fw)
	fillBackendRulesetFingerprint(ctx, fw)
}

func fillFirewalldHints(ctx context.Context, fw *payload.Firewall) {
	if !commandOnPath("firewall-cmd") {
		return
	}
	subCtx, cancel := context.WithTimeout(ctx, firewalldHintsCmdTimeout)
	zOut, err := exec.CommandContext(subCtx, "firewall-cmd", "--get-default-zone").Output()
	cancel()
	if err != nil {
		return
	}
	zone := strings.TrimSpace(string(zOut))
	if zone == "" {
		return
	}
	fw.FirewalldDefaultZone = shared.TruncateRunes(zone, 64)
	subCtx2, cancel2 := context.WithTimeout(ctx, firewalldHintsCmdTimeout)
	tOut, err := exec.CommandContext(subCtx2, "firewall-cmd", "--get-zone-target", "--zone", zone).Output()
	cancel2()
	if err == nil {
		fw.FirewalldZoneTarget = shared.TruncateRunes(strings.TrimSpace(string(tOut)), 64)
	}
}

func fillUfwVerbose(ctx context.Context, fw *payload.Firewall) {
	path := ufwExecutablePath()
	if path == "" {
		return
	}
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(subCtx, path, "status", "verbose")
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

func fillBackendRulesetFingerprint(ctx context.Context, fw *payload.Firewall) {
	subCtx, cancel := context.WithTimeout(ctx, time.Duration(rulesetCaptureMillis)*time.Millisecond)
	defer cancel()
	raw, _ := captureRuleset(subCtx)
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
