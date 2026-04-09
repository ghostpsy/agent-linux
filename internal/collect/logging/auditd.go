//go:build linux

package logging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	auditctlTimeoutSeconds = 5
	maxAuditRulesFiles     = 48
	maxAuditRuleFileBytes  = 256 * 1024
)

func collectAuditdPosture() *payload.AuditdPosture {
	if !auditdSignalsLikely() {
		return nil
	}
	out := &payload.AuditdPosture{}
	out.UnitActive = systemdIsActiveFirst([]string{"auditd.service", "auditd"})
	ctx, cancel := context.WithTimeout(context.Background(), auditctlTimeoutSeconds)
	defer cancel()
	if _, err := exec.LookPath("auditctl"); err != nil {
		out.AuditctlUnavailableReason = shared.TruncateRunes("auditctl not on PATH", 256)
		out.RulesDropInFiles = hashAuditRulesDropIns()
		return out
	}
	cmd := exec.CommandContext(ctx, "auditctl", "-l")
	raw, err := cmd.Output()
	if err != nil {
		out.AuditctlUnavailableReason = shared.TruncateRunes(fmt.Sprintf("auditctl -l failed: %v", err), 256)
		out.RulesDropInFiles = hashAuditRulesDropIns()
		return out
	}
	lines := countAuditctlRuleLines(string(raw))
	out.RuleLineCount = &lines
	out.RulesDropInFiles = hashAuditRulesDropIns()
	return out
}

func auditdSignalsLikely() bool {
	if st, err := os.Stat("/etc/audit"); err == nil && st.IsDir() {
		return true
	}
	if systemdIsActiveFirst([]string{"auditd.service", "auditd"}) != "" {
		return true
	}
	if _, err := exec.LookPath("auditctl"); err == nil {
		return true
	}
	return false
}

func countAuditctlRuleLines(body string) int {
	n := 0
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n++
	}
	return n
}

func hashAuditRulesDropIns() []payload.AuditRulesFileHash {
	matches, err := filepath.Glob("/etc/audit/rules.d/*.rules")
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	var out []payload.AuditRulesFileHash
	for i, p := range matches {
		if i >= maxAuditRulesFiles {
			break
		}
		sum, err := sha256FileBounded(p, maxAuditRuleFileBytes)
		if err != nil {
			continue
		}
		out = append(out, payload.AuditRulesFileHash{Path: p, Sha256: sum})
	}
	return out
}

func sha256FileBounded(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	var buf = make([]byte, 32*1024)
	var read int64
	for read < maxBytes {
		n, rerr := f.Read(buf)
		if n > 0 {
			remain := maxBytes - read
			if int64(n) > remain {
				n = int(remain)
			}
			_, _ = h.Write(buf[:n])
			read += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
