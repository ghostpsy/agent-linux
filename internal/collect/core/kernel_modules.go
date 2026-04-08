//go:build linux

package core

import (
	"bufio"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxModuleLines = 512

var moduleDenylistSubstrings = []string{
	"dccp",
	"sctp",
	"rds",
	"tipc",
}

// CollectKernelModules lists loaded modules from /proc/modules (capped) with denylist hits.
func CollectKernelModules() *payload.KernelModulesBlock {
	out := &payload.KernelModulesBlock{Names: []string{}, DenylistMatches: []string{}}
	f, err := os.Open("/proc/modules")
	if err != nil {
		out.Error = "cannot read /proc/modules"
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	seenHit := make(map[string]struct{})
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]
		out.Names = append(out.Names, name)
		n++
		low := strings.ToLower(name)
		for _, sub := range moduleDenylistSubstrings {
			if strings.Contains(low, sub) {
				if _, ok := seenHit[name]; !ok {
					seenHit[name] = struct{}{}
					out.DenylistMatches = append(out.DenylistMatches, name)
				}
				break
			}
		}
		if n >= maxModuleLines {
			break
		}
	}
	return out
}
