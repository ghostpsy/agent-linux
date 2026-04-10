//go:build linux

package network

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxLegacyUnitSample = 16

const legacySystemctlListTimeout = 10 * time.Second

// CollectLegacyInsecureServices reports systemd unit/socket hints and inetd.conf presence.
func CollectLegacyInsecureServices(ctx context.Context) *payload.LegacyInsecureServices {
	out := &payload.LegacyInsecureServices{}
	ctx, cancel := context.WithTimeout(ctx, legacySystemctlListTimeout)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--no-legend").Output(); err == nil {
		lower := strings.ToLower(string(b))
		out.TelnetSuspected = strings.Contains(lower, "telnet")
		out.RshSuspected = strings.Contains(lower, "rsh") || strings.Contains(lower, "rshd")
		out.RloginSuspected = strings.Contains(lower, "rlogin")
		out.RexecSuspected = strings.Contains(lower, "rexec")
		out.VsftpdSuspected = strings.Contains(lower, "vsftpd")
		out.ProftpdSuspected = strings.Contains(lower, "proftpd")
		out.SystemdUnitNamesSample = sampleLegacyUnitLines(string(b))
	}
	if st, err := os.Stat("/etc/inetd.conf"); err == nil && !st.IsDir() {
		out.InetdConfPresent = true
		out.InetdConfNonCommentLines = countInetdNonCommentLines()
	}
	return out
}

func sampleLegacyUnitLines(statusOut string) []string {
	var out []string
	for _, line := range strings.Split(statusOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "telnet") || strings.Contains(low, "rsh") ||
			strings.Contains(low, "rlogin") || strings.Contains(low, "rexec") ||
			strings.Contains(low, "vsftpd") || strings.Contains(low, "proftpd") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				out = append(out, shared.TruncateRunes(fields[0], 128))
			}
		}
		if len(out) >= maxLegacyUnitSample {
			break
		}
	}
	return out
}

func countInetdNonCommentLines() int {
	b, err := shared.ReadFileBounded("/etc/inetd.conf", shared.DefaultConfigFileReadLimit)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}
