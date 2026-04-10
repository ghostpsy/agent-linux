//go:build linux

package software

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

var (
	reRedisBind        = regexp.MustCompile(`(?i)^\s*bind\s+(.+)$`)
	reRedisPort        = regexp.MustCompile(`(?i)^\s*port\s+(\d+)\s*$`)
	reRedisProtected   = regexp.MustCompile(`(?i)^\s*protected-mode\s+(\S+)\s*$`)
	reRedisRequirepass = regexp.MustCompile(`(?i)^\s*requirepass\s+\S+`)
)

// CollectRedisExposureFingerprint parses redis.conf candidates and redis-server unit state.
func CollectRedisExposureFingerprint(ctx context.Context) *payload.RedisExposureFingerprint {
	out := &payload.RedisExposureFingerprint{}
	out.UnitActiveState = systemdUnitActiveState([]string{"redis-server.service", "redis.service", "valkey.service"})
	paths := []string{"/etc/redis/redis.conf", "/etc/redis.conf", "/usr/local/etc/redis.conf"}
	for _, p := range paths {
		b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
		if err != nil {
			continue
		}
		out.ConfigPathUsed = p
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if m := reRedisBind.FindStringSubmatch(t); len(m) > 1 {
				out.Bind = strings.TrimSpace(m[1])
			}
			if m := reRedisPort.FindStringSubmatch(t); len(m) > 1 {
				if port, err := strconv.Atoi(m[1]); err == nil {
					pv := port
					out.Port = &pv
				}
			}
			if m := reRedisProtected.FindStringSubmatch(t); len(m) > 1 {
				out.ProtectedMode = strings.TrimSpace(m[1])
			}
			if reRedisRequirepass.MatchString(t) {
				t := true
				out.RequirepassPresent = &t
			}
		}
		break
	}
	return out
}

func systemdUnitActiveState(units []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, u := range units {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", u)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(out))
		if s != "" && s != "unknown" {
			return s
		}
	}
	return ""
}
