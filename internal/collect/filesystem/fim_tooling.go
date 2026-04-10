//go:build linux

package filesystem

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

var fimEvidenceCandidates = []string{
	"/etc/aide/aide.conf",
	"/etc/aide.conf",
	"/usr/sbin/aide",
	"/usr/sbin/aideinit",
	"/var/lib/aide/aide.db",
	"/var/lib/aide/aide.db.new",
	"/etc/tripwire/tw.cfg",
	"/etc/tripwire/tw.pol",
	"/usr/sbin/twprint",
	"/usr/sbin/siggen",
}

// CollectFileIntegrityTooling detects AIDE/Tripwire-style installation hints (no DB upload).
func CollectFileIntegrityTooling(ctx context.Context) *payload.FileIntegrityTooling {
	out := &payload.FileIntegrityTooling{}
	var evidence []string
	for _, p := range fimEvidenceCandidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			evidence = append(evidence, p)
			lp := strings.ToLower(p)
			switch {
			case strings.Contains(lp, "aide"):
				out.AideSuspected = true
			case strings.Contains(lp, "tripwire") || strings.Contains(lp, "tw."):
				out.TripwireSuspected = true
			}
		}
	}
	out.EvidencePaths = evidence
	out.SystemdUnitsSample = listSystemdFimUnits()
	out.LatestDbUtcHint = latestAideDbMtime()
	return out
}

func listSystemdFimUnits() []string {
	cmd := exec.Command("systemctl", "list-unit-files", "--type=service", "--no-legend")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var units []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := strings.ToLower(fields[0])
		if strings.Contains(name, "aide") || strings.Contains(name, "tripwire") {
			units = append(units, fields[0])
		}
		if len(units) >= 8 {
			break
		}
	}
	return units
}

func latestAideDbMtime() string {
	var best time.Time
	var bestPath string
	for _, p := range []string{"/var/lib/aide/aide.db", "/var/lib/aide/aide.db.new"} {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.ModTime().After(best) {
			best = st.ModTime()
			bestPath = p
		}
	}
	if bestPath == "" {
		return ""
	}
	return best.UTC().Format(time.RFC3339)
}
