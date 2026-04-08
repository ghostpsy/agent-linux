//go:build linux

package core

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	gopsutilproc "github.com/shirou/gopsutil/v4/process"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxHighRiskEntries = 24

// isLinuxKernelThread reports whether pid is kthreadd or a kernel thread (child of kthreadd, PID 2).
func isLinuxKernelThread(pid int32) bool {
	if pid == 2 {
		return true
	}
	if pid <= 0 {
		return false
	}
	path := filepath.Join("/proc", strconv.FormatInt(int64(pid), 10), "status")
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	ppid, ok := parsePPidFromProcStatus(string(data))
	return ok && ppid == 2
}

func parsePPidFromProcStatus(status string) (int, bool) {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		v, err := strconv.Atoi(fields[1])
		return v, err == nil
	}
	return 0, false
}

// CollectHighRiskProcessSurface samples TCP listeners and root-owned processes with exe/cmdline hints.
func CollectHighRiskProcessSurface() *payload.HighRiskProcessSurface {
	out := &payload.HighRiskProcessSurface{Items: []payload.HighRiskProcessEntry{}}
	portsByPID := listenerPortsByPID()
	procs, err := gopsutilproc.Processes()
	if err != nil {
		out.Error = "process enumeration failed"
		return out
	}
	var listenerPids []int32
	for pid := range portsByPID {
		listenerPids = append(listenerPids, pid)
	}
	var rootPids []int32
	for _, p := range procs {
		pid := p.Pid
		if pid <= 0 {
			continue
		}
		u, err := p.Username()
		if err != nil {
			continue
		}
		if u == "root" && !isLinuxKernelThread(pid) {
			rootPids = append(rootPids, pid)
		}
	}
	seen := make(map[int32]struct{})
	appendEntry := func(pid int32) bool {
		if isLinuxKernelThread(pid) {
			return true
		}
		if len(out.Items) >= maxHighRiskEntries {
			return false
		}
		if _, ok := seen[pid]; ok {
			return true
		}
		seen[pid] = struct{}{}
		ent := buildHighRiskEntry(pid, portsByPID[pid])
		out.Items = append(out.Items, ent)
		return true
	}
	for _, pid := range listenerPids {
		if !appendEntry(pid) {
			break
		}
	}
	for _, pid := range rootPids {
		if _, ok := seen[pid]; ok {
			continue
		}
		if !appendEntry(pid) {
			break
		}
	}
	return out
}

func listenerPortsByPID() map[int32][]int {
	conns, err := gopsutilnet.Connections("tcp")
	if err != nil {
		slog.Debug("high risk: net connections failed", "error", err)
		return nil
	}
	m := make(map[int32][]int)
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Pid <= 0 {
			continue
		}
		port := int(c.Laddr.Port)
		if port <= 0 || port > 65535 {
			continue
		}
		m[c.Pid] = append(m[c.Pid], port)
	}
	for pid, ports := range m {
		m[pid] = dedupeSortedInts(ports)
	}
	return m
}

func dedupeSortedInts(ports []int) []int {
	if len(ports) <= 1 {
		return ports
	}
	seen := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		seen[p] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func buildHighRiskEntry(pid int32, ports []int) payload.HighRiskProcessEntry {
	ent := payload.HighRiskProcessEntry{Pid: pid, ListenerPorts: ports}
	p, err := gopsutilproc.NewProcess(pid)
	if err != nil {
		ent.Reason = "process handle failed"
		return ent
	}
	u, err := p.Username()
	if err == nil {
		ent.User = shared.TruncateRunes(strings.TrimSpace(u), 64)
	} else {
		ent.User = "unknown"
	}
	exe, err := p.Exe()
	if err == nil {
		ent.ExePath = shared.TruncateRunes(exe, 512)
	}
	if strings.Contains(ent.ExePath, "(deleted)") {
		ent.BinaryDeleted = true
	}
	exePath := "/proc/" + strconv.FormatInt(int64(pid), 10) + "/exe"
	if link, err := os.Readlink(exePath); err == nil {
		if strings.Contains(link, "(deleted)") {
			ent.BinaryDeleted = true
			if ent.ExePath == "" {
				ent.ExePath = shared.TruncateRunes(link, 512)
			}
		}
	}
	cmdline, err := p.CmdlineSlice()
	if err == nil && len(cmdline) == 0 {
		ent.CmdlineEmpty = true
	}
	if len(ports) > 0 {
		ent.Reason = "tcp_listener"
	} else if ent.User == "root" {
		ent.Reason = "root_process"
	}
	return ent
}
