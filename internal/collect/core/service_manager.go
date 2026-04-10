//go:build linux

package core

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// CollectSystemdHealth reports systemd default target and running state when systemctl exists.
func CollectSystemdHealth(ctx context.Context) *payload.SystemdHealth {
	out := &payload.SystemdHealth{}
	if _, err := exec.LookPath("systemctl"); err != nil {
		out.SystemdPresent = false
		out.LegacyRunlevel = tryRunlevel()
		return out
	}
	out.SystemdPresent = true
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "systemctl", "get-default").Output(); err == nil {
		out.DefaultTarget = strings.TrimSpace(string(b))
	}
	if b, err := exec.CommandContext(ctx, "systemctl", "is-system-running").Output(); err == nil {
		out.IsSystemRunning = strings.TrimSpace(string(b))
	} else {
		out.IsSystemRunning = "unknown"
	}
	failed := countFailedUnits(ctx)
	if failed != nil {
		out.FailedUnitsCount = failed
	}
	return out
}

func countFailedUnits(ctx context.Context) *int {
	ctx2, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "systemctl", "--failed", "--no-legend", "--no-pager")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	n := 0
	const maxCount = 50
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n++
		if n >= maxCount {
			break
		}
	}
	return &n
}

func tryRunlevel() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "runlevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
