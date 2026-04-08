//go:build linux

package filesystem

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxPathEntries = 64

// CollectHostPath enumerates PATH directories with exists and world-writable flags (skips dirs under /home).
func CollectHostPath() *payload.HostPath {
	out := &payload.HostPath{Entries: []payload.PathEntry{}}
	raw := os.Getenv("PATH")
	if strings.TrimSpace(raw) == "" {
		return out
	}
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ":") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		cleaned := filepath.Clean(part)
		if strings.HasPrefix(cleaned, "/home/") {
			continue
		}
		if _, dup := seen[cleaned]; dup {
			continue
		}
		seen[cleaned] = struct{}{}
		fi, err := os.Stat(cleaned)
		if err != nil {
			out.Entries = append(out.Entries, payload.PathEntry{Path: cleaned, Exists: false, WorldWritable: false})
		} else {
			mode := fi.Mode().Perm()
			ww := mode&0o002 != 0
			out.Entries = append(out.Entries, payload.PathEntry{Path: cleaned, Exists: true, WorldWritable: ww})
		}
		if len(out.Entries) >= maxPathEntries {
			break
		}
	}
	return out
}
