//go:build linux

package core

import (
	"github.com/ghostpsy/agent-linux/internal/payload"
)

// CollectSysctlLiveProfile reads allowlisted /proc/sys keys (bounded).
func CollectSysctlLiveProfile() *payload.SysctlLiveBlock {
	out := &payload.SysctlLiveBlock{Items: []payload.SysctlKV{}}
	for _, key := range sysctlSecurityAllowlist {
		path := sysctlDotToProcPath(key)
		if path == "" {
			continue
		}
		val := readProcSysValue(path)
		if val == "" {
			continue
		}
		out.Items = append(out.Items, payload.SysctlKV{Key: key, Value: val})
	}
	return out
}
