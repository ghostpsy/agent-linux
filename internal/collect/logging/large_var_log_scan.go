//go:build linux

package logging

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	largeVarLogFileMinBytes = 50 << 20 // 50 MiB
	maxVarLogWalkEntries    = 512
	maxLargeVarLogReported  = 24
	maxLargeVarLogTracked   = 128
	maxVarLogScanDepth      = 2 // allow paths like /var/log/dir/file.log
)

func scanLargeVarLogFiles(patterns []string) ([]payload.LargeVarLogFileEntry, int) {
	root := "/var/log"
	if !varLogRootExists() {
		return nil, 0
	}
	var unrotated []payload.LargeVarLogFileEntry
	withoutHint := 0
	visited := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		visited++
		if visited > maxVarLogWalkEntries {
			return filepath.SkipAll
		}
		if d.IsDir() {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil || rel == "." {
				return nil
			}
			depth := strings.Count(rel, string(filepath.Separator))
			if depth >= maxVarLogScanDepth {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() < largeVarLogFileMinBytes {
			return nil
		}
		abs := path
		hint := logrotatePatternCoversFile(patterns, abs)
		if hint {
			return nil
		}
		withoutHint++
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			rel = filepath.Base(abs)
		}
		ent := payload.LargeVarLogFileEntry{RelPath: rel, SizeBytes: info.Size()}
		if len(unrotated) < maxLargeVarLogTracked {
			unrotated = append(unrotated, ent)
		}
		return nil
	})
	sort.Slice(unrotated, func(i, j int) bool { return unrotated[i].SizeBytes > unrotated[j].SizeBytes })
	if len(unrotated) > maxLargeVarLogReported {
		unrotated = unrotated[:maxLargeVarLogReported]
	}
	return unrotated, withoutHint
}

func varLogRootExists() bool {
	st, err := os.Stat("/var/log")
	return err == nil && st.IsDir()
}
