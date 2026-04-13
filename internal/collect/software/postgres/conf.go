//go:build linux

package postgres

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const (
	pgConfMaxIncludeDepth = 10
	pgConfMaxFiles        = 64
)

var (
	rePgConfKV        = regexp.MustCompile(`^\s*([a-zA-Z0-9_]+)\s*=\s*(.*)$`)
	rePgInclude       = regexp.MustCompile(`(?i)^\s*include\s*=\s*(.+)$`)
	rePgIncludeIf     = regexp.MustCompile(`(?i)^\s*include_if_exists\s*=\s*(.+)$`)
	rePgIncludeDir    = regexp.MustCompile(`(?i)^\s*include_dir\s*=\s*(.+)$`)
	reWeakCipherToken = regexp.MustCompile(`(?i)\b(LOW|EXPORT|DES|RC4|MD5|NULL)\b`)
)

type pgConfMerger struct {
	visited   map[string]bool
	filesRead int
	warnings  []string
	settings  map[string]string
}

func mergePostgresqlConf(entryPath string) (settings map[string]string, primaryPath string, warnings []string) {
	m := &pgConfMerger{visited: make(map[string]bool), settings: make(map[string]string)}
	ep := strings.TrimSpace(entryPath)
	if ep == "" || !shared.FileExistsRegular(ep) {
		return nil, "", nil
	}
	abs, err := filepath.Abs(ep)
	if err != nil {
		abs = ep
	}
	m.processFile(abs, 0)
	return m.settings, abs, m.warnings
}

func (m *pgConfMerger) processFile(absPath string, depth int) {
	if depth > pgConfMaxIncludeDepth {
		m.warnings = append(m.warnings, fmt.Sprintf("postgresql.conf include depth cap at %s", absPath))
		return
	}
	if m.filesRead >= pgConfMaxFiles {
		m.warnings = append(m.warnings, "postgresql.conf file read cap reached")
		return
	}
	absPath = filepath.Clean(absPath)
	if m.visited[absPath] {
		return
	}
	m.visited[absPath] = true
	m.filesRead++
	baseDir := filepath.Dir(absPath)
	b, err := shared.ReadFileBounded(absPath, shared.DefaultConfigFileReadLimit)
	if err != nil {
		m.warnings = append(m.warnings, fmt.Sprintf("postgresql.conf unreadable %s: %v", absPath, err))
		return
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if mm := rePgInclude.FindStringSubmatch(line); len(mm) == 2 {
			raw := stripConfComment(strings.TrimSpace(mm[1]))
			p := resolveIncludePath(baseDir, unquoteConfValue(strings.TrimSpace(raw)))
			if p != "" {
				m.processFile(p, depth+1)
			}
			continue
		}
		if mm := rePgIncludeIf.FindStringSubmatch(line); len(mm) == 2 {
			raw := stripConfComment(strings.TrimSpace(mm[1]))
			p := resolveIncludePath(baseDir, unquoteConfValue(strings.TrimSpace(raw)))
			if p != "" && shared.FileExistsRegular(p) {
				m.processFile(p, depth+1)
			}
			continue
		}
		if mm := rePgIncludeDir.FindStringSubmatch(line); len(mm) == 2 {
			raw := stripConfComment(strings.TrimSpace(mm[1]))
			dir := resolveIncludePath(baseDir, unquoteConfValue(strings.TrimSpace(raw)))
			if dir == "" {
				continue
			}
			ents, err := os.ReadDir(dir)
			if err != nil {
				m.warnings = append(m.warnings, fmt.Sprintf("include_dir unreadable %s: %v", dir, err))
				continue
			}
			var names []string
			for _, e := range ents {
				if e.IsDir() {
					continue
				}
				n := e.Name()
				if strings.HasSuffix(strings.ToLower(n), ".conf") {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				m.processFile(filepath.Join(dir, n), depth+1)
			}
			continue
		}
		mat := rePgConfKV.FindStringSubmatch(line)
		if len(mat) != 3 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(mat[1]))
		val := stripConfComment(strings.TrimSpace(mat[2]))
		val = unquoteConfValue(val)
		m.settings[key] = val
	}
}

func resolveIncludePath(baseDir, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(baseDir, p))
}

func unquoteConfValue(v string) string {
	if len(v) >= 2 {
		if v[0] == '\'' && v[len(v)-1] == '\'' {
			return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
		}
		if v[0] == '"' && v[len(v)-1] == '"' {
			return strings.ReplaceAll(v[1:len(v)-1], `""`, `"`)
		}
	}
	return v
}

func stripConfComment(v string) string {
	var b strings.Builder
	inSQuote, inDQuote := false, false
	runes := []rune(v)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\'' && !inDQuote:
			inSQuote = !inSQuote
			b.WriteRune(r)
		case r == '"' && !inSQuote:
			inDQuote = !inDQuote
			b.WriteRune(r)
		case r == '#' && !inSQuote && !inDQuote:
			return strings.TrimSpace(b.String())
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func resolveHbaPath(settings map[string]string, dataDir, confDir string) string {
	raw := strings.TrimSpace(settings["hba_file"])
	raw = unquoteConfValue(raw)
	if raw == "" {
		candidate := filepath.Join(confDir, "pg_hba.conf")
		if shared.FileExistsRegular(candidate) {
			return candidate
		}
		if dataDir != "" {
			candidate = filepath.Join(dataDir, "pg_hba.conf")
			if shared.FileExistsRegular(candidate) {
				return candidate
			}
		}
		return ""
	}
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	if dataDir != "" {
		return filepath.Clean(filepath.Join(dataDir, raw))
	}
	return filepath.Clean(filepath.Join(confDir, raw))
}

func resolveDataDirectory(settings map[string]string, confDir string) string {
	raw := strings.TrimSpace(settings["data_directory"])
	raw = unquoteConfValue(raw)
	if raw == "" {
		return ""
	}
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Clean(filepath.Join(confDir, raw))
}

func settingString(settings map[string]string, key string) *string {
	v := strings.TrimSpace(settings[key])
	if v == "" {
		return nil
	}
	v = unquoteConfValue(v)
	if v == "" {
		return nil
	}
	s := shared.TruncateRunes(v, 2048)
	return &s
}

func settingInt(settings map[string]string, key string) *int {
	v := strings.TrimSpace(settings[key])
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 1<<30 {
		return nil
	}
	return &n
}
