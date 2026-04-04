//go:build linux

package collect

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// collectPackagesUpdatesRPM uses dnf or yum check-update (and --security) with English locale.
func collectPackagesUpdatesRPM(bin, manager string) *payload.PackagesUpdates {
	env := envLocaleC()
	out, err := combinedOutputEnv(env, bin, "check-update")
	pending, _ := parseDnfCheckUpdate(out)
	secOut, secErr := combinedOutputEnv(env, bin, "check-update", "--security")
	secCount, secNames := parseDnfCheckUpdate(secOut)
	if secErr != nil {
		slog.Warn("rpm check-update --security failed", "manager", manager, "error", secErr)
		secCount, secNames = 0, nil
	}
	if err != nil && pending == 0 && len(strings.TrimSpace(string(out))) == 0 {
		return &payload.PackagesUpdates{
			Manager:                    manager,
			LastPackageIndexRefreshUTC: rpmFamilyCacheLastRefreshUTC(),
		}
	}
	if err != nil && pending == 0 {
		slog.Warn("rpm check-update failed; packages_updates may be empty", "manager", manager, "error", err)
	}
	return &payload.PackagesUpdates{
		Manager:                    manager,
		LastPackageIndexRefreshUTC: rpmFamilyCacheLastRefreshUTC(),
		PendingUpdatesCount:        pending,
		SecurityUpdatesCount:       secCount,
		SecurityUpdatesSample:      capSecuritySample(secNames),
	}
}

func rpmFamilyCacheLastRefreshUTC() string {
	t, ok := rpmFamilyCacheLastRefreshTime()
	if !ok {
		return ""
	}
	return payload.AgentUtcRFC3339(t)
}

func rpmFamilyCacheLastRefreshTime() (time.Time, bool) {
	var best time.Time
	var have bool
	for _, dir := range []string{"/var/cache/dnf", "/var/cache/yum"} {
		if t, ok := maxModTimeDirShallow(dir); ok {
			if !have || t.After(best) {
				best = t
			}
			have = true
		}
	}
	if !have {
		return time.Time{}, false
	}
	return best.UTC(), true
}

func maxModTimeDirShallow(dir string) (time.Time, bool) {
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
		st, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if st.ModTime().After(max) {
			max = st.ModTime()
		}
	}
	return max.UTC(), true
}

// parseDnfCheckUpdate parses `dnf|yum check-update` (and --security) output for package rows.
func parseDnfCheckUpdate(output []byte) (count int, names []string) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || dnfCheckUpdateSkipLine(line) {
			continue
		}
		fields := strings.Fields(line)
		name, ok := dnfCheckUpdateRow(fields)
		if !ok {
			continue
		}
		count++
		names = append(names, name)
	}
	return count, names
}

func dnfCheckUpdateSkipLine(line string) bool {
	switch {
	case strings.HasPrefix(line, "Last metadata"):
		return true
	case strings.HasPrefix(line, "Obsoleting"):
		return true
	case strings.HasPrefix(line, "Security:"):
		return true
	case strings.HasPrefix(line, "==="):
		return true
	case strings.HasPrefix(line, "Matched"):
		return true
	case strings.HasPrefix(line, "Package"):
		return true
	case strings.HasPrefix(line, "Upgrading"):
		return true
	case strings.HasPrefix(line, "Determining"):
		return true
	case strings.HasPrefix(line, "Metadata"):
		return true
	case strings.HasPrefix(line, "Loaded"):
		return true
	}
	return false
}

// dnfCheckUpdateRow handles two layouts: "name.arch ver repo" or "name arch ver repo".
func dnfCheckUpdateRow(fields []string) (name string, ok bool) {
	if len(fields) < 2 {
		return "", false
	}
	if len(fields) >= 3 && rpmKnownArch(fields[1]) {
		return truncateRunes(fields[0], 256), true
	}
	if strings.Contains(fields[0], ".") {
		return truncateRunes(rpmStripArch(fields[0]), 256), true
	}
	return "", false
}

func rpmKnownArch(s string) bool {
	switch s {
	case "x86_64", "aarch64", "noarch", "i686", "i386", "ppc64le", "s390x", "armv7hl", "armhfp":
		return true
	default:
		return false
	}
}

func rpmStripArch(pkgArch string) string {
	parts := strings.Split(pkgArch, ".")
	if len(parts) < 2 {
		return pkgArch
	}
	last := parts[len(parts)-1]
	if rpmKnownArch(last) {
		return strings.Join(parts[:len(parts)-1], ".")
	}
	return pkgArch
}
