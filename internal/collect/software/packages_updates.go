//go:build linux

package software

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxSecurityUpdatesSample = 32

const packageManagerExecTimeout = 6 * time.Minute

// CollectPackagesUpdates fills pending/security counts, installed package count, and a capped list of security-only package names.
// Prefers apt (Debian/Ubuntu), then dnf, then yum (RHEL family), then apk (Alpine), then pacman (Arch-style).
func CollectPackagesUpdates(ctx context.Context) *payload.PackagesUpdates {
	if err := shared.ScanContextError(ctx); err != nil {
		return &payload.PackagesUpdates{Error: err.Error()}
	}
	var pu *payload.PackagesUpdates
	switch {
	case fileExists("/usr/bin/apt-get"):
		pu = collectPackagesUpdatesApt(ctx)
	default:
		if p, err := exec.LookPath("dnf"); err == nil {
			pu = collectPackagesUpdatesRPM(ctx, p, "dnf")
		} else if p, err := exec.LookPath("yum"); err == nil {
			pu = collectPackagesUpdatesRPM(ctx, p, "yum")
		} else if p, err := exec.LookPath("apk"); err == nil {
			pu = collectPackagesUpdatesApk(ctx, p)
		} else if fileExists("/usr/bin/pacman") {
			pu = &payload.PackagesUpdates{Manager: "pacman"}
		} else {
			return &payload.PackagesUpdates{Error: shared.CollectionNote("no supported package manager found (apt, dnf, yum, apk, or pacman).")}
		}
	}
	if pu != nil {
		pu.InstalledPackageCount = countInstalledPackageLines()
	}
	return pu
}

func capSecuritySample(names []string) []string {
	if len(names) > maxSecurityUpdatesSample {
		names = names[:maxSecurityUpdatesSample]
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = shared.TruncateRunes(n, 256)
	}
	return out
}

func combinedOutputEnv(ctx context.Context, env []string, name string, arg ...string) ([]byte, error) {
	if err := shared.ScanContextError(ctx); err != nil {
		return nil, err
	}
	subCtx, cancel := context.WithTimeout(ctx, packageManagerExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, name, arg...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
