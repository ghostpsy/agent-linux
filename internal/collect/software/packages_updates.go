//go:build linux

package software

import (
	"os"
	"os/exec"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxSecurityUpdatesSample = 32

// CollectPackagesUpdates fills pending/security counts, installed package count, and a capped list of security-only package names.
// Prefers apt (Debian/Ubuntu), then dnf, then yum (RHEL family), then apk (Alpine), then pacman (Arch-style).
// The second return is a non-empty message when no package manager is available.
func CollectPackagesUpdates() (*payload.PackagesUpdates, string) {
	var pu *payload.PackagesUpdates
	switch {
	case fileExists("/usr/bin/apt-get"):
		pu = collectPackagesUpdatesApt()
	default:
		if p, err := exec.LookPath("dnf"); err == nil {
			pu = collectPackagesUpdatesRPM(p, "dnf")
		} else if p, err := exec.LookPath("yum"); err == nil {
			pu = collectPackagesUpdatesRPM(p, "yum")
		} else if p, err := exec.LookPath("apk"); err == nil {
			pu = collectPackagesUpdatesApk(p)
		} else if fileExists("/usr/bin/pacman") {
			pu = &payload.PackagesUpdates{Manager: "pacman"}
		} else {
			return nil, shared.CollectionNote("no supported package manager found (apt, dnf, yum, apk, or pacman).")
		}
	}
	if pu != nil {
		pu.InstalledPackageCount = countInstalledPackageLines()
	}
	return pu, ""
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

func combinedOutputEnv(env []string, name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
