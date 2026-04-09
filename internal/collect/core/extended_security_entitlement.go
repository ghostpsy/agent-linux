//go:build linux

package core

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxAptSourceScanBytes = 96 * 1024

// applyDistroPaidExtendedSecurityActive sets distro_paid_extended_security_active when the agent can
// prove paid extended security (Ubuntu Pro ESM, Debian ELTS / Freexian-style apt sources).
func applyDistroPaidExtendedSecurityActive(osReleaseID string, out *payload.OSInfo) {
	if out == nil {
		return
	}
	id := strings.ToLower(strings.TrimSpace(osReleaseID))
	t := true
	switch id {
	case "ubuntu":
		if ubuntuPaidExtendedESMEnabled() {
			out.DistroPaidExtendedSecurityActive = &t
		}
	case "debian":
		if debianEltsStyleSourcesPresent() {
			out.DistroPaidExtendedSecurityActive = &t
		}
	default:
		return
	}
}

type uaLikeStatus struct {
	Attached *bool `json:"attached"`
	Services []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"services"`
}

func ubuntuPaidExtendedESMEnabled() bool {
	for _, argv := range [][]string{
		{"pro", "status", "--format", "json"},
		{"ubuntu-advantage", "status", "--format", "json"},
	} {
		cmd := exec.Command(argv[0], argv[1:]...)
		out, err := cmd.Output()
		if err != nil || len(out) == 0 {
			continue
		}
		if uaJSONIndicatesESMEnabled(out) {
			return true
		}
	}
	return false
}

func uaJSONIndicatesESMEnabled(raw []byte) bool {
	var st uaLikeStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return false
	}
	if st.Attached != nil && !*st.Attached {
		return false
	}
	for _, s := range st.Services {
		n := strings.ToLower(strings.TrimSpace(s.Name))
		if !strings.HasPrefix(n, "esm-") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(s.Status), "enabled") {
			return true
		}
	}
	return false
}

func debianEltsStyleSourcesPresent() bool {
	paths := []string{"/etc/apt/sources.list"}
	if m, err := filepath.Glob("/etc/apt/sources.list.d/*.list"); err == nil {
		paths = append(paths, m...)
	}
	if m, err := filepath.Glob("/etc/apt/sources.list.d/*.sources"); err == nil {
		paths = append(paths, m...)
	}
	for _, p := range paths {
		if aptSourceFileMentionsElts(p) {
			return true
		}
	}
	return false
}

func aptSourceFileMentionsElts(path string) bool {
	data, err := readFileLimited(path, maxAptSourceScanBytes)
	if err != nil || len(data) == 0 {
		return false
	}
	low := strings.ToLower(string(data))
	return strings.Contains(low, "elts.debian.org") ||
		strings.Contains(low, "freexian") ||
		strings.Contains(low, "deb.freexian.com")
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
