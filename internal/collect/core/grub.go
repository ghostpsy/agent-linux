//go:build linux

package core

import (
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	defaultGrubPath = "/etc/default/grub"
	maxGrubCmdline  = 8192
	maxGrubCfgPeek  = 4096
)

// CollectGrubSnapshot parses /etc/default/grub and optionally peeks grub.cfg (no secrets).
func CollectGrubSnapshot() *payload.GrubSnapshot {
	out := &payload.GrubSnapshot{}
	data, err := os.ReadFile(defaultGrubPath)
	if err != nil {
		out.Error = "default grub file not readable"
		return out
	}
	out.DefaultGrubPath = defaultGrubPath
	lines := strings.Split(string(data), "\n")
	var cmdlineParts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "GRUB_CMDLINE_LINUX=") || strings.HasPrefix(line, "GRUB_CMDLINE_LINUX_DEFAULT=") {
			v := parseGrubQuotedValue(line[strings.Index(line, "=")+1:])
			if v != "" {
				cmdlineParts = append(cmdlineParts, strings.TrimSpace(v))
			}
		}
		if strings.HasPrefix(line, "GRUB_TIMEOUT=") || strings.HasPrefix(line, "GRUB_TIMEOUT_STYLE=") {
			if out.GrubTimeout == "" {
				out.GrubTimeout = strings.TrimSpace(line[strings.Index(line, "=")+1:])
			}
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "grub_password") || strings.Contains(low, "password_pbkdf2") {
			out.PasswordReferencePresent = true
		}
	}
	if len(cmdlineParts) > 0 {
		out.GrubCmdlineLinux = shared.TruncateRunes(strings.Join(cmdlineParts, " "), maxGrubCmdline)
	}
	for _, p := range []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"} {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		peek, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if len(peek) > maxGrubCfgPeek {
			peek = peek[:maxGrubCfgPeek]
		}
		out.GrubCfgReadablePath = p
		peekS := string(peek)
		if strings.Contains(strings.ToLower(peekS), "password") {
			out.PasswordReferencePresent = true
		}
		break
	}
	return out
}

func parseGrubQuotedValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return strings.TrimSpace(raw[1 : len(raw)-1])
	}
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return strings.TrimSpace(raw[1 : len(raw)-1])
	}
	return raw
}
