//go:build linux

package collect

import (
	"log/slog"
	"strings"

	"github.com/shirou/gopsutil/v4/host"

	"ghostpsy/agent-linux/internal/payload"
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
			hostname = truncateRunes(h, maxHostnameRunes)
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
		Pretty:             truncateRunes(pretty, 512),
		Kernel:             truncateRunes(kernel, 512),
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
			out.KernelArch = truncateRunes(ka, 64)
		}
	}
	return out, hostname
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
