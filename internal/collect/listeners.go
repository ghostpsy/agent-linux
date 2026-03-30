//go:build linux

package collect

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	gopsutilproc "github.com/shirou/gopsutil/v4/process"

	"ghostpsy/agent-linux/internal/payload"
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
		out[i] = payload.Listener{
			Port:         work[i].port,
			Bind:         truncateRunes(work[i].bind, 64),
			Process:      truncateRunes(work[i].process, 256),
			BindScope:    bs,
			ExposureRisk: er,
		}
	}
	return out
}

// processNameFromPID uses gopsutil process.Name (comm / process title).
func processNameFromPID(pid int32) string {
	if pid <= 0 {
		return "unknown"
	}
	p, err := gopsutilproc.NewProcess(pid)
	if err != nil {
		return "unknown"
	}
	name, err := p.Name()
	if err != nil {
		return "unknown"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "unknown"
	}
	return name
}
