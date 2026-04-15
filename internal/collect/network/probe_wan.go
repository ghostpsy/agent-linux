//go:build linux

package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	probeDialTimeout  = 3 * time.Second
	probeGlobalBudget = 30 * time.Second
)

func isPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback()
}

// collectRawPublicIPs returns non-redacted public unicast IPs from local interfaces.
func collectRawPublicIPs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		slog.Debug("probe_wan: cannot enumerate interfaces", "error", err)
		return nil
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if isPublicIP(ip) {
				out = append(out, ip)
			}
		}
	}
	return out
}

// ProbeInternetListeners performs TCP connect probes against internet-exposed listeners
// via the machine's own public IPs. Only listeners with exposure_risk == "internet_exposed"
// are probed. The result is a copy of the input slice with WanProbeOpen set.
func ProbeInternetListeners(ctx context.Context, listeners []payload.Listener, hn *payload.HostNetwork) []payload.Listener {
	if !hostNetworkHasPublicIP(hn) {
		return listeners
	}

	publicIPs := collectRawPublicIPs()
	if len(publicIPs) == 0 {
		slog.Debug("probe_wan: no public IPs found for probing")
		return listeners
	}

	deadline, cancel := context.WithTimeout(ctx, probeGlobalBudget)
	defer cancel()

	out := make([]payload.Listener, len(listeners))
	copy(out, listeners)

	for i := range out {
		if out[i].ExposureRisk != "internet_exposed" {
			continue
		}
		open := probePort(deadline, publicIPs, out[i].Port)
		out[i].WanProbeOpen = &open
	}
	return out
}

// probePort tries a TCP connect to any of the public IPs on the given port.
// Returns true if at least one connection succeeds.
func probePort(ctx context.Context, publicIPs []net.IP, port int) bool {
	for _, ip := range publicIPs {
		if ctx.Err() != nil {
			return false
		}
		addr := fmt.Sprintf("%s:%d", formatIPForDial(ip), port)
		dialer := net.Dialer{Timeout: probeDialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			slog.Debug("probe_wan: port open", "addr", addr)
			return true
		}
		slog.Debug("probe_wan: port closed or filtered", "addr", addr, "error", err)
	}
	return false
}

// formatIPForDial wraps IPv6 addresses in brackets for net.Dial.
func formatIPForDial(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	return "[" + ip.String() + "]"
}
