//go:build linux

package logging

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const systemdCmdTimeout = 5 * time.Second

func systemdIsActiveFirst(unitNames []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), systemdCmdTimeout)
	defer cancel()
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	for _, u := range unitNames {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", u)
		out, err := cmd.Output()
		s := strings.TrimSpace(string(out))
		if err != nil && s == "" {
			continue
		}
		if s != "" {
			return s
		}
	}
	return ""
}

// systemdUnitActiveBool is true when is-active is exactly "active", false for other non-empty states, nil when unknown.
func systemdUnitActiveBool(unitNames []string) *bool {
	return unitActiveBoolFromString(systemdIsActiveFirst(unitNames))
}

func unitActiveBoolFromString(isActiveLine string) *bool {
	s := strings.TrimSpace(isActiveLine)
	if s == "" {
		return nil
	}
	v := s == "active"
	return &v
}
