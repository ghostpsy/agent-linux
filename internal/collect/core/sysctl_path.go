//go:build linux

package core

import (
	"os"
	"path/filepath"
	"strings"
)

// sysctlDotToProcPath maps "net.ipv4.ip_forward" to /proc/sys/net/ipv4/ip_forward.
func sysctlDotToProcPath(dotted string) string {
	dotted = strings.TrimSpace(dotted)
	if dotted == "" {
		return ""
	}
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return ""
	}
	return filepath.Join(append([]string{"/proc/sys"}, parts...)...)
}

// readProcSysValue reads a trimmed string from path; empty if missing/unreadable.
func readProcSysValue(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
