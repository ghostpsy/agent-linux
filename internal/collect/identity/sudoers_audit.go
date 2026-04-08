//go:build linux

package identity

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const sudoersMaxFileBytes = 512 * 1024

// CollectSudoersAudit performs a structural sudoers scan without transmitting full rule bodies.
func CollectSudoersAudit() *payload.SudoersAudit {
	out := &payload.SudoersAudit{}
	mainPath := "/etc/sudoers"
	b, err := readSudoersFileLimited(mainPath)
	if err != nil {
		out.Error = "sudoers could not be read"
		return out
	}
	out.FilesScanned = append(out.FilesScanned, mainPath)
	scanSudoersContent(string(b), out, true)
	dir := "/etc/sudoers.d"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b2, err2 := readSudoersFileLimited(p)
		if err2 != nil {
			continue
		}
		out.FilesScanned = append(out.FilesScanned, p)
		scanSudoersContent(string(b2), out, false)
	}
	return out
}

func readSudoersFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, sudoersMaxFileBytes))
}

func scanSudoersContent(content string, out *payload.SudoersAudit, isMain bool) {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#") {
			if isMain && strings.HasPrefix(strings.ToLower(strings.TrimPrefix(t, "#")), "includedir") {
				out.IncludedirCount++
			}
			continue
		}
		upper := strings.ToUpper(t)
		if strings.Contains(upper, "NOPASSWD") {
			out.NopasswdMentionCount++
		}
		if strings.Contains(t, "ALL=(ALL") || strings.Contains(t, "ALL=(ALL:ALL") {
			out.AllAllPatternCount++
		}
		if strings.Contains(upper, "NOPASSWD: ALL") {
			out.WildcardRiskLineCount++
		}
		applyDefaultsLine(t, out)
	}
}

func applyDefaultsLine(t string, out *payload.SudoersAudit) {
	low := strings.ToLower(t)
	if !strings.HasPrefix(low, "defaults") {
		return
	}
	if strings.Contains(low, "!requiretty") {
		out.DefaultsRequirettyPresent = false
	} else if strings.Contains(low, "requiretty") {
		out.DefaultsRequirettyPresent = true
	}
	if strings.Contains(low, "!use_pty") {
		out.DefaultsUsePtyPresent = false
	} else if strings.Contains(low, "use_pty") {
		out.DefaultsUsePtyPresent = true
	}
	if strings.Contains(low, "!visiblepw") {
		out.DefaultsVisiblepwInvertedPresent = true
	}
}
