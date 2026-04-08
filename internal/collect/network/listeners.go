//go:build linux

package network

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	gopsutilproc "github.com/shirou/gopsutil/v4/process"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxListeners = 256

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// listenerWork holds a listening socket before JSON truncation.
type listenerWork struct {
	port    int
	bind    string
	process string
	pid     int32
}

// CollectListeners lists TCP listeners via gopsutil net.Connections (same idea as psutil net_connections).
func CollectListeners(hn *payload.HostNetwork) []payload.Listener {
	work, err := collectListenerWork()
	if err != nil {
		slog.Warn("gopsutil net.Connections failed", "error", err)
		return nil
	}
	return listenerWorkToPayload(work, hn)
}

// CollectListenerPIDs returns distinct PIDs that own a TCP LISTEN socket (bounded by maxListeners).
func CollectListenerPIDs() []int32 {
	conns, err := gopsutilnet.Connections("tcp")
	if err != nil {
		return nil
	}
	seen := make(map[int32]struct{})
	var pids []int32
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Pid <= 0 {
			continue
		}
		if _, ok := seen[c.Pid]; ok {
			continue
		}
		seen[c.Pid] = struct{}{}
		pids = append(pids, c.Pid)
		if len(pids) >= maxListeners {
			break
		}
	}
	return pids
}

func collectListenerWork() ([]listenerWork, error) {
	conns, err := gopsutilnet.Connections("tcp")
	if err != nil {
		return nil, err
	}
	var work []listenerWork
	seen := make(map[string]struct{})
	for _, c := range conns {
		if c.Status != "LISTEN" {
			continue
		}
		port := int(c.Laddr.Port)
		if port <= 0 || port > 65535 {
			continue
		}
		ip := strings.TrimSpace(c.Laddr.IP)
		if ip == "" {
			continue
		}
		bind := net.JoinHostPort(ip, strconv.Itoa(port))
		if _, dup := seen[bind]; dup {
			continue
		}
		seen[bind] = struct{}{}
		work = append(work, listenerWork{
			port:    port,
			bind:    bind,
			process: processNameFromPID(c.Pid),
			pid:     c.Pid,
		})
		if len(work) >= maxListeners {
			break
		}
	}
	return work, nil
}

func listenerWorkToPayload(work []listenerWork, hn *payload.HostNetwork) []payload.Listener {
	out := make([]payload.Listener, len(work))
	for i := range work {
		bs, er := classifyListenerExposure(work[i].bind, hn)
		unit, ok := systemdUnitFromCgroup(work[i].pid)
		ent := payload.Listener{
			Port:         work[i].port,
			Bind:         truncateRunes(work[i].bind, 64),
			Process:      truncateRunes(work[i].process, 256),
			ListenPid:    work[i].pid,
			SystemdUnit:  shared.TruncateRunes(unit, 128),
			BindScope:    bs,
			ExposureRisk: er,
		}
		if work[i].pid > 0 && !ok {
			ent.SystemdUnitMissing = true
		}
		out[i] = ent
	}
	return out
}

// processNameFromPID uses gopsutil process.Name (comm / process title).
func processNameFromPID(pid int32) string {
	if pid <= 0 {
		slog.Debug("listener pid is not positive", "pid", pid)
		return "unknown"
	}
	p, err := gopsutilproc.NewProcess(pid)
	if err != nil {
		slog.Debug("cannot create process handle for listener pid", "pid", pid, "error", err)
		return "unknown"
	}
	name, err := p.Name()
	if err != nil {
		slog.Debug("cannot resolve process name for listener pid", "pid", pid, "error", err)
		return "unknown"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		slog.Debug("resolved empty process name for listener pid", "pid", pid)
		return "unknown"
	}
	return name
}
