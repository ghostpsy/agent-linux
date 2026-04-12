//go:build linux

package packages

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const apkManagerName = "apk"

// Matches apk simulate transaction lines, e.g. "(1/3) Upgrading busybox (1.36.1-r20 -> 1.36.1-r21)".
var reApkSimulateChange = regexp.MustCompile(`^\(\d+/\d+\) (Upgrading|Installing|Downgrading|Reinstalling) `)

func collectPackagesUpdatesApk(ctx context.Context, apkBin string) *payload.PackagesUpdates {
	env := shared.EnvLocaleC()
	out, err := combinedOutputEnv(ctx, env, apkBin, "upgrade", "-s")
	pending := parseApkUpgradeSimulate(out)
	if err != nil && pending == 0 && len(strings.TrimSpace(string(out))) == 0 {
		return &payload.PackagesUpdates{
			Manager:                    apkManagerName,
			LastPackageIndexRefreshUTC: apkCacheLastRefreshUTC(),
		}
	}
	if err != nil && pending == 0 {
		slog.Warn("apk upgrade -s failed; packages_updates may be empty", "error", err)
	}
	return &payload.PackagesUpdates{
		Manager:                    apkManagerName,
		LastPackageIndexRefreshUTC: apkCacheLastRefreshUTC(),
		PendingUpdatesCount:        pending,
	}
}

func apkCacheLastRefreshUTC() string {
	t, ok := apkCacheLastRefreshTime()
	if !ok {
		return ""
	}
	return payload.AgentUtcRFC3339(t)
}

func apkCacheLastRefreshTime() (time.Time, bool) {
	return maxModTimeApkCacheDir("/var/cache/apk")
}

func maxModTimeApkCacheDir(dir string) (time.Time, bool) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return time.Time{}, false
	}
	max := st.ModTime()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return max.UTC(), true
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		fs, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if fs.ModTime().After(max) {
			max = fs.ModTime()
		}
	}
	return max.UTC(), true
}

func parseApkUpgradeSimulate(output []byte) int {
	n := 0
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if reApkSimulateChange.MatchString(line) {
			n++
		}
	}
	return n
}
