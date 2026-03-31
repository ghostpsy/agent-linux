//go:build linux

package collect

import (
	"log/slog"
	"net"
	"regexp"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"

	"ghostpsy/agent-linux/internal/payload"
)

const maxDiskFilesystems = 48
const maxNetworkIfaces = 64
const maxPublicIPCandidates = 24

// loIfaceName matches Linux "lo", "lo0", … and typical loopback device names.
var loIfaceName = regexp.MustCompile(`^lo\d*$`)

// CollectHostDisk reports mount usage via gopsutil disk.Partitions(false) + disk.Usage.
// The second return is non-empty when host disk usage could not be collected (error message for ingest).
func CollectHostDisk() (*payload.HostDisk, string) {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil, collectionNote("disk partition list could not be read.")
	}
	if len(parts) == 0 {
		return nil, ""
	}
	seen := make(map[string]struct{})
	var fses []payload.FilesystemEntry
	for _, p := range parts {
		if len(fses) >= maxDiskFilesystems {
			break
		}
		mp := p.Mountpoint
		if mp == "" {
			continue
		}
		if _, dup := seen[mp]; dup {
			continue
		}
		seen[mp] = struct{}{}
		u, err := disk.Usage(mp)
		if err != nil || u == nil {
			if err != nil {
				slog.Debug("disk usage collection failed", "mountpoint", mp, "error", err)
			}
			continue
		}
		if u.Total == 0 {
			continue
		}
		availGB := float64(u.Free) / (1024 * 1024 * 1024)
		usedPct := int(u.UsedPercent + 0.5)
		if usedPct > 100 {
			usedPct = 100
		}
		ent := payload.FilesystemEntry{
			Mount:   truncateRunes(mp, 512),
			Fstype:  p.Fstype,
			UsedPct: usedPct,
			AvailGB: availGB,
		}
		if u.InodesTotal > 0 {
			ip := int(u.InodesUsedPercent + 0.5)
			if ip > 100 {
				ip = 100
			}
			ent.InodesUsedPct = &ip
		}
		fses = append(fses, ent)
	}
	if len(fses) == 0 {
		return nil, collectionNote("no filesystem usage statistics could be collected.")
	}
	return &payload.HostDisk{Filesystems: fses}, ""
}

// CollectHostNetwork summarizes interfaces and public-IP hints via gopsutil net.Interfaces.
func CollectHostNetwork() (*payload.HostNetwork, string) {
	ifs, err := gopsutilnet.Interfaces()
	if err != nil {
		return nil, collectionNote("network interfaces could not be enumerated.")
	}
	if len(ifs) == 0 {
		return nil, collectionNote("no network interfaces were reported.")
	}
	var (
		out        []payload.NetworkIface
		public     []string
		hasPub4    bool
		hasPub6    bool
		seenPublic = make(map[string]struct{})
	)
	for _, iface := range ifs {
		if len(out) >= maxNetworkIfaces {
			break
		}
		isLoop := false
		for _, fl := range iface.Flags {
			if strings.EqualFold(fl, "loopback") {
				isLoop = true
				break
			}
		}
		if isLoop || loIfaceName.MatchString(iface.Name) {
			continue
		}
		isDocker := strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "br-") ||
			strings.HasPrefix(iface.Name, "veth")
		var addrs []payload.IfaceAddress
		for _, a := range iface.Addrs {
			ipStr, scope := ifaceAddrScope(a.Addr)
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			if !isRealInterfaceIP(ip) {
				continue
			}
			addrs = append(addrs, payload.IfaceAddress{IP: ipStr, Scope: scope})
			if isPublicUnicastIP(ip) {
				if ip.To4() != nil {
					hasPub4 = true
				} else {
					hasPub6 = true
				}
				if len(public) < maxPublicIPCandidates {
					if _, dup := seenPublic[ipStr]; !dup {
						seenPublic[ipStr] = struct{}{}
						public = append(public, ipStr)
					}
				}
			}
		}
		if len(addrs) == 0 {
			continue
		}
		t, f := true, false
		ni := payload.NetworkIface{Name: iface.Name, Addresses: addrs}
		ni.IsLoopback = &f
		if isDocker {
			ni.IsDockerBridge = &t
		}
		out = append(out, ni)
	}
	hn := &payload.HostNetwork{
		Interfaces:         out,
		PublicIPCandidates: public,
	}
	if hasPub4 {
		hn.HasPublicIPv4 = &hasPub4
	}
	if hasPub6 {
		hn.HasPublicIPv6 = &hasPub6
	}
	return hn, ""
}

func ifaceAddrScope(addr string) (ip string, scope string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "unknown"
	}
	if ip0, ipNet, err := net.ParseCIDR(addr); err == nil {
		return ip0.String(), classifyAddrScope(ip0, ipNet)
	}
	ip0 := net.ParseIP(strings.Split(addr, "/")[0])
	if ip0 == nil {
		return "", "unknown"
	}
	return ip0.String(), classifyAddrScope(ip0, nil)
}

func classifyAddrScope(ip net.IP, _ *net.IPNet) string {
	switch {
	case ip.IsLoopback():
		return "host"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link"
	case ip.IsGlobalUnicast():
		return "global"
	default:
		return "unknown"
	}
}

// isRealInterfaceIP returns true for unicast addresses we want on inventory (not loopback / unspecified / multicast).
func isRealInterfaceIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	if ip.IsMulticast() {
		return false
	}
	return ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast()
}

func isPublicUnicastIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	return true
}
