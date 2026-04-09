//go:build linux

package logging

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const journalctlDiskUsageTimeout = 5 * time.Second

const maxJournaldConfPaths = 32

func collectJournaldPosture() *payload.JournaldPosture {
	if !journaldSignalsLikely() {
		return nil
	}
	out := &payload.JournaldPosture{}
	out.UnitActive = systemdUnitActiveBool([]string{"systemd-journald.service", "systemd-journald.socket"})
	for _, p := range journaldConfigPaths() {
		if len(out.ConfigPathsRead) >= maxJournaldConfPaths {
			break
		}
		b, err := readFileBounded(p)
		if err != nil {
			continue
		}
		out.ConfigPathsRead = append(out.ConfigPathsRead, p)
		for _, line := range strings.Split(string(b), "\n") {
			applyJournaldConfLine(out, line)
		}
	}
	fillJournalctlDiskUsage(out)
	return out
}

func journaldSignalsLikely() bool {
	if st, err := os.Stat("/etc/systemd/journald.conf"); err == nil && !st.IsDir() {
		return true
	}
	if m, err := filepath.Glob("/etc/systemd/journald.conf.d/*.conf"); err == nil && len(m) > 0 {
		return true
	}
	if _, err := exec.LookPath("journalctl"); err == nil {
		return true
	}
	if systemdIsActiveFirst([]string{"systemd-journald.service", "systemd-journald.socket"}) != "" {
		return true
	}
	return false
}

func journaldConfigPaths() []string {
	var out []string
	if st, err := os.Stat("/etc/systemd/journald.conf"); err == nil && !st.IsDir() {
		out = append(out, "/etc/systemd/journald.conf")
	}
	if m, err := filepath.Glob("/etc/systemd/journald.conf.d/*.conf"); err == nil {
		sort.Strings(m)
		out = append(out, m...)
	}
	return out
}

func applyJournaldConfLine(out *payload.JournaldPosture, line string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return
	}
	if strings.HasPrefix(line, "[") {
		return
	}
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	key := strings.TrimSpace(strings.ToLower(k))
	val := strings.TrimSpace(v)
	switch key {
	case "storage":
		out.Storage = shared.TruncateRunes(val, 64)
	case "forwardtosyslog":
		if b, ok := parseJournaldBool(val); ok {
			out.ForwardToSyslog = &b
		}
	case "forwardtowall":
		if b, ok := parseJournaldBool(val); ok {
			out.ForwardToWall = &b
		}
	case "forwardtoconsole":
		if b, ok := parseJournaldBool(val); ok {
			out.ForwardToConsole = &b
		}
	case "compress":
		if b, ok := parseJournaldBool(val); ok {
			out.Compress = &b
		}
	case "seal":
		if b, ok := parseJournaldBool(val); ok {
			out.Seal = &b
		}
	case "systemmaxuse":
		out.SystemMaxUse = shared.TruncateRunes(val, 64)
	case "runtimemaxuse":
		out.RuntimeMaxUse = shared.TruncateRunes(val, 64)
	case "maxretentionsec":
		out.MaxRetentionSec = shared.TruncateRunes(val, 64)
	}
}

func parseJournaldBool(val string) (bool, bool) {
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func fillJournalctlDiskUsage(out *payload.JournaldPosture) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), journalctlDiskUsageTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--disk-usage")
	raw, err := cmd.Output()
	if err != nil {
		return
	}
	t := strings.TrimSpace(string(raw))
	if t == "" {
		return
	}
	lines := strings.Split(t, "\n")
	out.JournalctlDiskUsageSummary = shared.TruncateRunes(strings.TrimSpace(lines[0]), 512)
}
