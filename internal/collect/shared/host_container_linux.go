//go:build linux

package shared

import (
	"os"
	"strings"
)

// HostIsContainerized reports dockerenv/cgroup hints (best-effort).
func HostIsContainerized() *bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return BoolPtr(true)
	}
	b, err := ReadFileBounded("/proc/self/cgroup", 16<<10)
	if err != nil {
		return BoolPtr(false)
	}
	s := strings.ToLower(string(b))
	if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") {
		return BoolPtr(true)
	}
	return BoolPtr(false)
}
