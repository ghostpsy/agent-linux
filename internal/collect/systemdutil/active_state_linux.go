//go:build linux

package systemdutil

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const systemctlIsActiveTimeout = 4 * time.Second

// MapActiveStateForPosture maps systemd ActiveState to running|stopped|unknown.
// The services collector may join substate as "active/running".
func MapActiveStateForPosture(active string) string {
	low := strings.ToLower(strings.TrimSpace(active))
	if low == "" {
		return ""
	}
	primary := low
	if i := strings.Index(low, "/"); i >= 0 {
		primary = low[:i]
	}
	switch primary {
	case "active", "reloading":
		return "running"
	case "inactive", "failed":
		return "stopped"
	default:
		return "unknown"
	}
}

// SystemctlIsActiveState runs systemctl is-active (bounded). Returns running, stopped, or unknown.
func SystemctlIsActiveState(ctx context.Context, unit string) string {
	if unit == "" {
		return "unknown"
	}
	subCtx, cancel := context.WithTimeout(ctx, systemctlIsActiveTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, "systemctl", "is-active", unit)
	out, _ := cmd.CombinedOutput()
	state := strings.TrimSpace(strings.ToLower(string(out)))
	switch state {
	case "active":
		return "running"
	case "inactive", "failed":
		return "stopped"
	default:
		if state != "" {
			return "unknown"
		}
	}
	return "unknown"
}
