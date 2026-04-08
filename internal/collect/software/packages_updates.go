//go:build linux

package software

import (
	"os"
	"os/exec"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxSecurityUpdatesSample = 32

// CollectPackagesUpdates fills pending/security counts and a capped list of security-only package names.
// Prefers apt (Debian/Ubuntu), then dnf, then yum (RHEL family).
// The second return is a non-empty message when no package manager is available.
func CollectPackagesUpdates() (*payload.PackagesUpdates, string) {
	switch {
	case fileExists("/usr/bin/apt-get"):
		return collectPackagesUpdatesApt(), ""
	default:
		if p, err := exec.LookPath("dnf"); err == nil {
			return collectPackagesUpdatesRPM(p, "dnf"), ""
		}
		if p, err := exec.LookPath("yum"); err == nil {
			return collectPackagesUpdatesRPM(p, "yum"), ""
		}
		return nil, shared.CollectionNote("no supported package manager found (apt, dnf, or yum).")
	}
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
