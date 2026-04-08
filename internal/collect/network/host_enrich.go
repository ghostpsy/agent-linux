//go:build linux

package network

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxResolvSampleLines = 12

// EnrichHostNetwork adds resolver snapshot and link-layer flags (IPv6, promiscuous).
func EnrichHostNetwork(hn *payload.HostNetwork) {
	if hn == nil {
		return
	}
	fillResolvConf(hn)
	fillIfaceIPv6Hints(hn)
	fillIfacePromiscFromSysfs(hn)
}

func fillResolvConf(hn *payload.HostNetwork) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return
	}
	content := string(b)
	sc := bufio.NewScanner(strings.NewReader(content))
	var sample []string
	stub := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ns := fields[1]
				hn.ResolvConfNameservers = append(hn.ResolvConfNameservers, shared.TruncateRunes(ns, 64))
				if ns == "127.0.0.53" || ns == "::1" {
					stub = true
				}
			}
		}
		if strings.HasPrefix(low, "domain") || strings.HasPrefix(low, "search") {
			fields := strings.Fields(line)
			for _, f := range fields[1:] {
				hn.ResolvConfSearchDomains = append(hn.ResolvConfSearchDomains, shared.TruncateRunes(f, 128))
			}
		}
		if len(sample) < maxResolvSampleLines {
			sample = append(sample, shared.TruncateRunes(line, 256))
		}
	}
	hn.ResolvConfSampleLines = sample
	if stub {
		t := true
		hn.SystemdResolvedStub = &t
	}
}

func fillIfaceIPv6Hints(hn *payload.HostNetwork) {
	for i := range hn.Interfaces {
		v := false
		for _, a := range hn.Interfaces[i].Addresses {
			ip := net.ParseIP(a.IP)
			if ip != nil && ip.To4() == nil {
				v = true
				break
			}
		}
		hn.Interfaces[i].Ipv6Enabled = &v
	}
}
