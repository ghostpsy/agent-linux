//go:build linux

package core

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
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
	if res, err := privexec.Run(ctx, privexec.SystemdDefaultTarget); err == nil {
		out.DefaultTarget = strings.TrimSpace(string(res.Stdout))
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
	res, err := privexec.Run(ctx2, privexec.SystemdFailedUnits)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
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
