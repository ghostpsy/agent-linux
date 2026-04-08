//go:build linux

package core

import (
	"log/slog"
	"os/exec"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/shirou/gopsutil/v4/host"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxHostnameRunes = 253

// CollectOSInfo sends pretty/kernel, raw /etc/os-release fields, and gopsutil host.Info.
// The API derives distro_id / distro_version_id / distro_name for EOL (see backend src/ingest/os_normalize).
// The second return is the host name from host.Info (for dashboard titles), or "" if unavailable.
func CollectOSInfo() (payload.OSInfo, string) {
	rel := parseOSRelease()
	hi, err := host.Info()
	if err != nil {
		slog.Warn("gopsutil host.Info failed", "error", err)
	}

	var kernel string
	var hostname string
	if hi != nil {
		kernel = strings.TrimSpace(hi.KernelVersion)
		if h := strings.TrimSpace(hi.Hostname); h != "" {
			hostname = shared.TruncateRunes(h, maxHostnameRunes)
		}
	}
	if kernel == "" && err == nil {
		slog.Warn("kernel version empty from gopsutil host.Info")
	}

	pretty := strings.TrimSpace(rel.PrettyName)
	if pretty == "" && hi != nil {
		pretty = platformPrettyFromHost(hi)
	}
	if pretty == "" {
		pretty = "Linux"
	}

	out := payload.OSInfo{
		Pretty:             shared.TruncateRunes(pretty, 512),
		Kernel:             shared.TruncateRunes(kernel, 512),
		OSReleaseID:        strings.TrimSpace(rel.ID),
		OSReleaseVersionID: strings.TrimSpace(rel.VersionID),
		OSReleaseVersion:   strings.TrimSpace(rel.Version),
		OSReleaseName:      strings.TrimSpace(rel.Name),
	}
	if hi != nil {
		out.Platform = strings.TrimSpace(hi.Platform)
		out.PlatformFamily = strings.TrimSpace(hi.PlatformFamily)
		out.PlatformVersion = strings.TrimSpace(hi.PlatformVersion)
		if ka := strings.TrimSpace(hi.KernelArch); ka != "" {
			out.KernelArch = shared.TruncateRunes(ka, 64)
		}
	}
	return out, hostname
}

// CollectFqdn derives a UI FQDN: dotted /etc/hostname if present, then hostname -f, -A, and
// shortHostname + hostname -d (GNU) when a DNS domain suffix is available.
func CollectFqdn(shortHostname string) string {
	if f := fqdnFromEtcHostname(); f != "" {
		return shared.TruncateRunes(f, maxHostnameRunes)
	}
	outF, _ := exec.Command("hostname", "-f").Output()
	outA, _ := exec.Command("hostname", "-A").Output()
	outD, _ := exec.Command("hostname", "-d").Output()
	resolved := resolveFqdnFromParts(shortHostname, string(outF), string(outA), string(outD))
	if resolved == "" {
		return ""
	}
	return shared.TruncateRunes(resolved, maxHostnameRunes)
}

func platformPrettyFromHost(hi *host.InfoStat) string {
	if hi == nil {
		return ""
	}
	pl := strings.TrimSpace(hi.Platform)
	ver := strings.TrimSpace(hi.PlatformVersion)
	if pl == "" {
		return ""
	}
	if ver != "" {
		return pl + " " + ver
	}
	return pl
}
