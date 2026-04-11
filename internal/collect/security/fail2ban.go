//go:build linux

package security

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

const (
	fail2banCmdTimeout   = 4 * time.Second
	fail2banMaxJailDFiles = 32
)

func collectFail2ban(ctx context.Context) *payload.Fail2banPosture {
	out := &payload.Fail2banPosture{Present: false}
	if ctx.Err() != nil {
		out.Error = ctx.Err().Error()
		return out
	}
	if !fail2banInstalled(ctx) {
		return out
	}
	out.Present = true
	out.UnitActiveState = fail2banSystemdIsActive(ctx, "fail2ban.service")
	out.UnitFileState = fail2banSystemdIsEnabled(ctx, "fail2ban.service")
	if p, err := exec.LookPath("fail2ban-client"); err == nil {
		out.Fail2banClientPath = p
		out.VersionSummary = shared.TruncateRunes(fail2banFirstLine(ctx, p, "--version"), 512)
	}
	paths, bodies := readFail2banJailConfigs()
	out.ConfigPathsRead = paths
	if len(bodies) == 0 {
		return out
	}
	merged := mergeFail2banIniBodies(bodies)
	out.EnabledJails = merged.EnabledJails
	if merged.JailSectionCountHint > 0 {
		n := merged.JailSectionCountHint
		out.JailSectionCountHint = &n
	}
	out.DefaultBantime = merged.DefaultBantime
	out.DefaultFindtime = merged.DefaultFindtime
	out.DefaultMaxRetry = merged.DefaultMaxRetry
	return out
}

func fail2banInstalled(ctx context.Context) bool {
	if st, err := os.Stat("/etc/fail2ban"); err == nil && st.IsDir() {
		if _, err := os.Stat("/etc/fail2ban/jail.conf"); err == nil {
			return true
		}
		if _, err := os.Stat("/etc/fail2ban/jail.local"); err == nil {
			return true
		}
		if matches, _ := filepath.Glob("/etc/fail2ban/jail.d/*.conf"); len(matches) > 0 {
			return true
		}
	}
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", "fail2ban.service", "--no-legend", "--no-pager").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "fail2ban")
}

func fail2banSystemdIsActive(parent context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fail2banSystemdIsEnabled(parent context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", "is-enabled", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fail2banFirstLine(parent context.Context, exe string, args ...string) string {
	ctx, cancel := context.WithTimeout(parent, fail2banCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func readFail2banJailConfigs() (paths []string, files []fail2banNamedConfig) {
	limit := shared.DefaultConfigFileReadLimit
	try := func(p string) {
		raw, err := shared.ReadFileBounded(p, limit)
		if err != nil {
			return
		}
		paths = append(paths, p)
		files = append(files, fail2banNamedConfig{Path: p, Body: raw})
	}
	try("/etc/fail2ban/jail.conf")
	try("/etc/fail2ban/jail.local")
	matches, err := filepath.Glob("/etc/fail2ban/jail.d/*.conf")
	if err != nil {
		return paths, files
	}
	sort.Strings(matches)
	if len(matches) > fail2banMaxJailDFiles {
		matches = matches[:fail2banMaxJailDFiles]
	}
	for _, p := range matches {
		try(p)
	}
	return paths, files
}
