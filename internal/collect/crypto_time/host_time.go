//go:build linux

package crypto_time

import (
	"context"
	"log/slog"
	"os/exec"
	"time"

	"github.com/beevik/ntp"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const ntpPoolServer = "0.pool.ntp.org"

// CollectHostTime sets utc_now, tries an SNTP query for offset_ms, and detects a running timesync daemon.
func CollectHostTime(ctx context.Context) *payload.HostTime {
	now := time.Now()
	ht := &payload.HostTime{
		UtcNow:         payload.AgentUtcRFC3339(now),
		TimesyncDaemon: detectTimesyncDaemon(ctx),
	}
	switch ht.TimesyncDaemon {
	case "chrony", "systemd-timesyncd", "ntp":
		t := true
		ht.NtpActive = &t
	case "none":
		f := false
		ht.NtpActive = &f
	}
	if err := shared.ScanContextError(ctx); err != nil {
		return ht
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

const daemonCheckTimeout = 2 * time.Second

// timesyncDaemons maps the process that keeps a clock right to what we call it.
//
// Ordered: chrony and timesyncd are what modern distributions ship, ntpd is what
// older ones have. A machine running two would be unusual, and the first found is
// as good an answer as any.
var timesyncDaemons = []struct{ process, label string }{
	{"chronyd", "chrony"},
	{"systemd-timesyncd", "systemd-timesyncd"},
	{"ntpd", "ntp"},
}

// detectTimesyncDaemon says what is keeping this machine's clock right, if
// anything.
//
// It looks for the process, not for a systemd unit. Asking `systemctl is-active`
// was the only question here, and on a machine with no systemd the answer was
// always "none" — so an Ubuntu 14.04 host where Solve had just installed ntp,
// and where ntpd was up and stayed up, reported no time daemon on the very next
// scan and was offered the same fix again.
//
// A daemon is running or it is not, whatever started it. Upstart, sysvinit and
// systemd all agree about the process table.
func detectTimesyncDaemon(parent context.Context) string {
	return timesyncDaemonFrom(func(name string) bool {
		subCtx, cancel := context.WithTimeout(parent, daemonCheckTimeout)
		defer cancel()
		// pgrep -x matches the whole process name, so "ntpd" does not match
		// "ntpdate", which is a one-shot and keeps no clock right.
		return exec.CommandContext(subCtx, "pgrep", "-x", name).Run() == nil
	})
}

// timesyncDaemonFrom is the rule on its own, so it can be tested without a
// machine that happens to run one.
func timesyncDaemonFrom(isRunning func(process string) bool) string {
	for _, candidate := range timesyncDaemons {
		if isRunning(candidate.process) {
			return candidate.label
		}
	}
	return "none"
}
