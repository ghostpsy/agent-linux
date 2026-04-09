//go:build linux

package logging

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/shirou/gopsutil/v4/disk"
)

const (
	maxLogrotateSampleLines = 12
	maxLogrotateDirFiles    = 64
	logUsageHighPct         = 90
)

func collectLogrotateDiskPosture() *payload.LogrotateDiskPosture {
	out := &payload.LogrotateDiskPosture{}
	mainPath := "/etc/logrotate.conf"
	if st, err := os.Stat(mainPath); err == nil && !st.IsDir() {
		out.MainConfPresent = true
		if b, err := readFileBounded(mainPath); err == nil {
			out.MainConfIncludeLinesSample = sampleLogrotateLines(string(b), func(s string) bool {
				t := strings.ToLower(strings.TrimSpace(s))
				return strings.HasPrefix(t, "include ") || strings.HasPrefix(t, "tabooext") || strings.HasPrefix(t, "compress")
			}, 6)
		}
	}
	out.VarLogStanzaHint, out.VarLogDirectiveSampleLines = scanLogrotateForVarLog()
	patterns := collectLogrotatePathPatterns()
	largeFiles, noRot := scanLargeVarLogFiles(patterns)
	if len(largeFiles) > 0 {
		out.LargeVarLogFiles = largeFiles
	}
	if noRot > 0 {
		out.LargeVarLogWithoutRotationHintCount = &noRot
	}
	fillVarLogDiskUsage(out)
	return out
}

func sampleLogrotateLines(body string, keep func(string) bool, max int) []string {
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if keep(line) && len(lines) < max {
			lines = append(lines, shared.TruncateRunes(t, 512))
		}
	}
	return lines
}

func scanLogrotateForVarLog() (bool, []string) {
	var samples []string
	found := false
	dir := "/etc/logrotate.d"
	ents, err := os.ReadDir(dir)
	if err == nil {
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for i, ent := range ents {
			if i >= maxLogrotateDirFiles {
				break
			}
			if ent.IsDir() || len(samples) >= maxLogrotateSampleLines {
				continue
			}
			p := filepath.Join(dir, ent.Name())
			b, err := readFileBounded(p)
			if err != nil {
				continue
			}
			body := string(b)
			if !strings.Contains(body, "/var/log") {
				continue
			}
			found = true
			for _, line := range strings.Split(body, "\n") {
				t := strings.TrimSpace(line)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				lower := strings.ToLower(t)
				if strings.Contains(lower, "rotate") || strings.Contains(lower, "maxage") || strings.Contains(lower, "size") || strings.Contains(lower, "weekly") || strings.Contains(lower, "daily") {
					if len(samples) < maxLogrotateSampleLines {
						samples = append(samples, shared.TruncateRunes(t, 512))
					}
				}
			}
		}
	}
	return found, samples
}

func fillVarLogDiskUsage(out *payload.LogrotateDiskPosture) {
	for _, tryPath := range []string{"/var/log", "/var"} {
		u, err := disk.Usage(tryPath)
		if err != nil || u == nil || u.Total == 0 {
			continue
		}
		out.VarLogUsagePath = tryPath
		pct := int(u.UsedPercent + 0.5)
		if pct > 100 {
			pct = 100
		}
		out.VarLogMountUsedPct = &pct
		high := pct >= logUsageHighPct
		out.LogPartitionUsageHigh = &high
		return
	}
	out.Error = shared.CollectionNote("log volume usage could not be read.")
}
