//go:build linux

package software

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const aptManagerName = "apt"

func collectPackagesUpdatesApt(ctx context.Context) *payload.PackagesUpdates {
	env := shared.EnvLocaleC()
	out, err := combinedOutputEnv(ctx, env, "apt-get", "-s", "dist-upgrade")
	pending, sec, secNames := parseAptGetSimulateDistUpgrade(out)
	if pending == 0 {
		if aptBin, e := exec.LookPath("apt"); e == nil {
			listOut, lerr := combinedOutputEnv(ctx, env, aptBin, "list", "--upgradable")
			p2, s2, n2 := parseAptListUpgradable(listOut)
			if p2 > 0 {
				pending, sec, secNames = p2, s2, n2
			} else if lerr != nil {
				slog.Warn("apt list --upgradable failed", "error", lerr)
			}
		}
	}
	if err != nil && pending == 0 && len(strings.TrimSpace(string(out))) == 0 {
		return &payload.PackagesUpdates{
			Manager:                    aptManagerName,
			LastPackageIndexRefreshUTC: aptPackageIndexLastRefreshUTC(),
		}
	}
	if err != nil && pending == 0 {
		slog.Warn("apt-get simulate dist-upgrade failed; packages_updates may be empty", "error", err)
	}
	return &payload.PackagesUpdates{
		Manager:                    aptManagerName,
		LastPackageIndexRefreshUTC: aptPackageIndexLastRefreshUTC(),
		PendingUpdatesCount:        pending,
		SecurityUpdatesCount:       sec,
		SecurityUpdatesSample:      capSecuritySample(secNames),
	}
}

const (
	aptPeriodicUpdateStamp = "/var/lib/apt/periodic/update-success-stamp"
	aptListsDir            = "/var/lib/apt/lists"
)

func aptPackageIndexLastRefreshUTC() string {
	t, ok := aptPackageIndexLastRefreshTime()
	if !ok {
		return ""
	}
	return payload.AgentUtcRFC3339(t)
}

func aptPackageIndexLastRefreshTime() (time.Time, bool) {
	var best time.Time
	var have bool
	if st, err := os.Stat(aptPeriodicUpdateStamp); err == nil && !st.IsDir() {
		best = st.ModTime()
		have = true
	}
	if t, ok := maxModTimeAptListsDir(aptListsDir); ok {
		if !have || t.After(best) {
			best = t
		}
		have = true
	}
	if !have {
		return time.Time{}, false
	}
	return best.UTC(), true
}

func maxModTimeAptListsDir(dir string) (time.Time, bool) {
	dst, err := os.Stat(dir)
	if err != nil || !dst.IsDir() {
		return time.Time{}, false
	}
	max := dst.ModTime()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return max.UTC(), true
	}
	for _, e := range entries {
		name := e.Name()
		if name == "partial" || name == "lock" || e.IsDir() {
			continue
		}
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if st.ModTime().After(max) {
			max = st.ModTime()
		}
	}
	return max.UTC(), true
}

// parseAptGetSimulateDistUpgrade parses English "Inst …" lines; secNames lists only security-related upgrades.
func parseAptGetSimulateDistUpgrade(output []byte) (pending, security int, secNames []string) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pending++
		if strings.Contains(strings.ToLower(line), "security") {
			security++
			secNames = append(secNames, fields[1])
		}
	}
	return pending, security, secNames
}

// parseAptListUpgradable parses `apt list --upgradable` output; secNames lists only security-related lines.
func parseAptListUpgradable(output []byte) (pending, security int, secNames []string) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "WARNING:") || line == "Listing..." {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		tok := fields[0]
		name, _, ok := strings.Cut(tok, "/")
		if !ok || name == "" {
			continue
		}
		pending++
		if strings.Contains(strings.ToLower(line), "security") {
			security++
			secNames = append(secNames, name)
		}
	}
	return pending, security, secNames
}
