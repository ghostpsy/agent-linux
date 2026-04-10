//go:build linux

package logging

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const maxLogrotatePathPatterns = 256

// collectLogrotatePathPatterns returns absolute path patterns from /etc/logrotate.conf and /etc/logrotate.d/* (bounded).
func collectLogrotatePathPatterns() []string {
	seen := make(map[string]struct{})
	var out []string
	addAll := func(paths []string) {
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" || !strings.HasPrefix(p, "/") {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
			if len(out) >= maxLogrotatePathPatterns {
				return
			}
		}
	}
	if b, err := shared.ReadFileBounded("/etc/logrotate.conf", shared.DefaultConfigFileReadLimit); err == nil {
		addAll(parseLogrotatePathsFromBody(string(b)))
	}
	if len(out) >= maxLogrotatePathPatterns {
		return out
	}
	dir := "/etc/logrotate.d"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for i, ent := range ents {
		if i >= maxLogrotateDirFiles {
			break
		}
		if ent.IsDir() {
			continue
		}
		p := filepath.Join(dir, ent.Name())
		b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
		if err != nil {
			continue
		}
		addAll(parseLogrotatePathsFromBody(string(b)))
		if len(out) >= maxLogrotatePathPatterns {
			break
		}
	}
	return out
}

func parseLogrotatePathsFromBody(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.Contains(t, "{") {
			continue
		}
		before, _, _ := strings.Cut(t, "{")
		before = strings.TrimSpace(before)
		for _, tok := range strings.Fields(before) {
			if strings.HasPrefix(tok, "/") {
				out = append(out, tok)
			}
		}
	}
	return out
}

func logrotatePatternCoversFile(patterns []string, absFile string) bool {
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		ok, err := filepath.Match(pat, absFile)
		if err == nil && ok {
			return true
		}
	}
	return false
}
