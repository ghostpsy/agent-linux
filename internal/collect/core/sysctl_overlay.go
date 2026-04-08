//go:build linux

package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxSysctlDrift = 64

// CollectSysctlOverlay parses sysctl.conf and sysctl.d, compares to live values for drift.
func CollectSysctlOverlay() *payload.SysctlOverlayBlock {
	out := &payload.SysctlOverlayBlock{}
	var files []string
	if matches, err := filepath.Glob("/etc/sysctl.d/*.conf"); err == nil {
		sort.Strings(matches)
		files = append(files, matches...)
	}
	if st, err := os.Stat("/etc/sysctl.conf"); err == nil && !st.IsDir() {
		files = append(files, "/etc/sysctl.conf")
	}
	fileVals := make(map[string]string)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		out.ParsedFiles = append(out.ParsedFiles, f)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			key, val := parseSysctlLine(line)
			key = normalizeSysctlKey(key)
			if key == "" {
				continue
			}
			if _, ok := fileVals[key]; !ok {
				fileVals[key] = val
			}
		}
	}
	keysSorted := make([]string, 0, len(fileVals))
	for k := range fileVals {
		keysSorted = append(keysSorted, k)
	}
	sort.Strings(keysSorted)
	n := 0
	for _, key := range keysSorted {
		fv := fileVals[key]
		path := sysctlDotToProcPath(key)
		if path == "" {
			continue
		}
		live := readProcSysValue(path)
		if live == "" {
			continue
		}
		if normalizeSysctlVal(fv) != normalizeSysctlVal(live) {
			out.Drift = append(out.Drift, payload.SysctlDriftEntry{Key: key, FileValue: fv, LiveValue: live})
			n++
		}
		if n >= maxSysctlDrift {
			break
		}
	}
	return out
}

func parseSysctlLine(line string) (key, val string) {
	if i := strings.IndexAny(line, "="); i > 0 {
		key = strings.TrimSpace(line[:i])
		val = strings.TrimSpace(line[i+1:])
		val = strings.Trim(val, `"`)
		return key, val
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return parts[0], strings.Join(parts[1:], " ")
	}
	return "", ""
}

func normalizeSysctlVal(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Live /proc/sys values often use tabs; sysctl.conf uses spaces — compare token-wise.
	return strings.Join(strings.Fields(s), " ")
}

func normalizeSysctlKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.ReplaceAll(k, "/", ".")
	return k
}
