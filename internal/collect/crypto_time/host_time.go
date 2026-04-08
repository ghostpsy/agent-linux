//go:build linux

package crypto_time

import (
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/beevik/ntp"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const ntpPoolServer = "0.pool.ntp.org"

// CollectHostTime sets utc_now, tries an SNTP query for offset_ms, and detects a running timesync daemon.
func CollectHostTime() *payload.HostTime {
	now := time.Now()
	ht := &payload.HostTime{
		UtcNow:         payload.AgentUtcRFC3339(now),
		TimesyncDaemon: detectTimesyncDaemon(),
	}
	switch ht.TimesyncDaemon {
	case "chrony", "systemd-timesyncd", "ntp":
		t := true
		ht.NtpActive = &t
	case "none":
		f := false
		ht.NtpActive = &f
	}
	resp, err := ntp.QueryWithOptions(ntpPoolServer, ntp.QueryOptions{Timeout: 4 * time.Second})
	if err != nil {
		slog.Warn("ntp query failed", "server", ntpPoolServer, "error", err)
		return ht
	}
	if resp == nil {
		slog.Warn("ntp query returned nil response", "server", ntpPoolServer)
		return ht
	}
	if err := resp.Validate(); err != nil {
		slog.Warn("ntp response validation failed", "server", ntpPoolServer, "error", err)
		return ht
	}
	// Local clock vs NTP pool at scan time. The API may still set host_time.skew_vs_server_seconds
	// at ingest (agent utc_now vs server NTP)—a different reference and time, not a duplicate of this.
	ms := float64(resp.ClockOffset.Nanoseconds()) / 1e6
	ht.OffsetMs = &ms
	return ht
}

func detectTimesyncDaemon() string {
	checks := []struct {
		unit, label string
	}{
		{"chronyd", "chrony"},
		{"chrony", "chrony"},
		{"systemd-timesyncd", "systemd-timesyncd"},
		{"ntp", "ntp"},
		{"ntpd", "ntp"},
	}
	seen := make(map[string]struct{})
	for _, c := range checks {
		if _, dup := seen[c.unit]; dup {
			continue
		}
		seen[c.unit] = struct{}{}
		out, err := exec.Command("systemctl", "is-active", c.unit).Output()
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(out)) == "active" {
			return c.label
		}
	}
	return "none"
}
