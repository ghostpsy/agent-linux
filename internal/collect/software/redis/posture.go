//go:build linux

// Package redis collects bounded security posture for Redis/Valkey servers.
// No keyspace data, no ACL contents, no credential values.
package redis

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

var (
	reVersion      = regexp.MustCompile(`v=([\d]+\.[\d]+\.[\d]+)`)
	reBind         = regexp.MustCompile(`(?i)^\s*bind\s+(.+)$`)
	rePort         = regexp.MustCompile(`(?i)^\s*port\s+(\d+)\s*$`)
	reProtected    = regexp.MustCompile(`(?i)^\s*protected-mode\s+(\S+)\s*$`)
	reRequirepass  = regexp.MustCompile(`(?i)^\s*requirepass\s+\S+`)
	reTlsPort      = regexp.MustCompile(`(?i)^\s*tls-port\s+(\d+)\s*$`)
)

var (
	binNames     = []string{"redis-server"}
	commonPaths  = []string{"/usr/bin/redis-server", "/usr/local/bin/redis-server"}
	serviceNames = []string{"redis-server.service", "redis.service", "valkey.service"}
	configPaths  = []string{"/etc/redis/redis.conf", "/etc/redis.conf", "/usr/local/etc/redis.conf"}
)

// CollectRedisPosture detects and collects Redis server posture.
// Returns nil when no redis-server binary is found.
func CollectRedisPosture(ctx context.Context, services []payload.ServiceEntry) *payload.RedisPosture {
	bin := resolveBinary()
	if bin == "" {
		return nil
	}

	out := &payload.RedisPosture{
		Detected: true,
		BinPath:  bin,
	}
	out.Version = extractVersion(ctx, bin)
	out.ServiceState = serviceState(ctx, services)
	parseConfig(out)
	if out.CollectorWarnings == nil {
		out.CollectorWarnings = []string{}
	}
	return out
}

func resolveBinary() string {
	for _, name := range binNames {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range commonPaths {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func extractVersion(ctx context.Context, bin string) *string {
	cmd := exec.CommandContext(ctx, bin, "-v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	m := reVersion.FindStringSubmatch(string(out))
	if len(m) >= 2 {
		return shared.StringPtr(m[1])
	}
	return nil
}

func serviceState(ctx context.Context, services []payload.ServiceEntry) *string {
	want := make(map[string]struct{}, len(serviceNames))
	for _, n := range serviceNames {
		want[n] = struct{}{}
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := systemdutil.MapActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	for _, n := range serviceNames {
		if st := systemdutil.SystemctlIsActiveState(ctx, n); st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	return nil
}

func parseConfig(out *payload.RedisPosture) {
	for _, p := range configPaths {
		b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if m := reBind.FindStringSubmatch(t); len(m) > 1 {
				out.Bind = shared.StringPtr(strings.TrimSpace(m[1]))
			}
			if m := rePort.FindStringSubmatch(t); len(m) > 1 {
				if port, err := strconv.Atoi(m[1]); err == nil {
					out.Port = shared.IntPtr(port)
				}
			}
			if m := reProtected.FindStringSubmatch(t); len(m) > 1 {
				out.ProtectedMode = shared.BoolPtr(strings.EqualFold(strings.TrimSpace(m[1]), "yes"))
			}
			if reRequirepass.MatchString(t) {
				out.RequirepassPresent = shared.BoolPtr(true)
			}
			if m := reTlsPort.FindStringSubmatch(t); len(m) > 1 {
				if port, err := strconv.Atoi(m[1]); err == nil && port > 0 {
					out.TlsEnabled = shared.BoolPtr(true)
				}
			}
		}
		return
	}
}
