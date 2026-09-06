//go:build linux

package systemdutil

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const systemctlIsActiveTimeout = 4 * time.Second

// MapActiveStateForPosture maps a service's reported state to
// running|stopped|unknown.
//
// It has to understand two vocabularies, because two collectors write to the
// same field. systemd says "active" and "inactive"; the sysvinit and Upstart
// collector says "running" outright. Understanding only systemd's words meant a
// sysvinit entry mapped to "unknown", so a service the machine had plainly
// reported as running was dropped as unreadable.
//
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
	case "active", "reloading", "running":
		return "running"
	case "inactive", "failed", "stopped", "dead":
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
