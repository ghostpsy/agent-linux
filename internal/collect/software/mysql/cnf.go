//go:build linux

package mysql

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
	mysqlCnfMaxIncludeDepth = 12
	mysqlCnfMaxFiles        = 96
)

var (
	reMysqlCnfInclude    = regexp.MustCompile(`(?i)^\s*!include\s+(.+)$`)
	reMysqlCnfIncludeDir = regexp.MustCompile(`(?i)^\s*!includedir\s+(.+)$`)
	reMysqlCnfSection    = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	reMysqlCnfOption     = regexp.MustCompile(`^\s*([-0-9A-Za-z_.]+)\s*(?:=\s*(.*))?$`)
	reMysqlPasswordLine  = regexp.MustCompile(`(?i)^\s*password\s*=\s*\S+`)
)

type mysqlCnfMerger struct {
	visited             map[string]bool
	filesRead           int
	warnings            []string
	opts                map[string]string
	passwordExposed     bool
	firstEntryPath      string
	firstEntryPathSet   bool
	baseDir             string
}

func normalizeMysqlCnfKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.ReplaceAll(k, "-", "_")
	return k
}

func isMysqlServerSection(sec string) bool {
	s := strings.ToLower(strings.TrimSpace(sec))
	switch s {
	case "mysqld", "mysqld_safe", "server":
		return true
	default:
		return false
	}
}

func isMysqlClientSection(sec string) bool {
	s := strings.ToLower(strings.TrimSpace(sec))
	switch s {
	case "client", "mysqladmin":
		return true
	default:
		return false
	}
}

func mergeMysqlMysqldOptions(entryPoints []string) (opts map[string]string, primaryPath string, passwordExposed bool, filesRead int, warnings []string) {
	m := &mysqlCnfMerger{
		visited: make(map[string]bool),
		opts:    make(map[string]string),
	}
	for _, ep := range entryPoints {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		if !shared.FileExistsRegular(ep) {
			continue
		}
		abs, err := filepath.Abs(ep)
		if err != nil {
			abs = ep
		}
		if !m.firstEntryPathSet {
			m.firstEntryPath = abs
			m.firstEntryPathSet = true
		}
		m.processFile(abs, 0)
	}
	return m.opts, m.firstEntryPath, m.passwordExposed, m.filesRead, m.warnings
}

func (m *mysqlCnfMerger) processFile(absPath string, depth int) {
	if depth > mysqlCnfMaxIncludeDepth {
		m.warnings = append(m.warnings, "mysql cnf include depth cap reached at "+absPath)
		return
	}
	if m.filesRead >= mysqlCnfMaxFiles {
		m.warnings = append(m.warnings, "mysql cnf file read cap reached")
		return
	}
	absPath = filepath.Clean(absPath)
	if m.visited[absPath] {
		return
	}
	m.visited[absPath] = true
	m.filesRead++
	m.baseDir = filepath.Dir(absPath)
	b, err := shared.ReadFileBounded(absPath, shared.DefaultConfigFileReadLimit)
	if err != nil {
		m.warnings = append(m.warnings, fmt.Sprintf("mysql cnf unreadable %s: %v", absPath, err))
		return
	}
	section := ""
	for _, rawLine := range logicalMysqlCnfLines(string(b)) {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if sm := reMysqlCnfSection.FindStringSubmatch(line); len(sm) == 2 {
			section = sm[1]
			continue
		}
		if isMysqlClientSection(section) && reMysqlPasswordLine.MatchString(line) {
			m.passwordExposed = true
		}
		if im := reMysqlCnfInclude.FindStringSubmatch(line); len(im) == 2 {
			inc := strings.Trim(strings.TrimSpace(im[1]), `"'`)
			child := m.resolveIncludePath(inc)
			m.processFile(child, depth+1)
			continue
		}
		if im := reMysqlCnfIncludeDir.FindStringSubmatch(line); len(im) == 2 {
			dir := strings.Trim(strings.TrimSpace(im[1]), `"'`)
			dir = m.resolveIncludePath(dir)
			m.processIncludeDir(dir, depth+1)
			continue
		}
		om := reMysqlCnfOption.FindStringSubmatch(line)
		if len(om) < 2 {
			continue
		}
		key := normalizeMysqlCnfKey(om[1])
		val := ""
		if len(om) > 2 {
			val = strings.TrimSpace(om[2])
			val = strings.Trim(val, `"'`)
		}
		if isMysqlServerSection(section) {
			m.opts[key] = val
		}
	}
}

func (m *mysqlCnfMerger) resolveIncludePath(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(m.baseDir, p))
}

func (m *mysqlCnfMerger) processIncludeDir(dir string, depth int) {
	if depth > mysqlCnfMaxIncludeDepth {
		return
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		m.warnings = append(m.warnings, fmt.Sprintf("mysql cnf !includedir missing or not a directory: %s", dir))
		return
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.cnf"))
	if err != nil {
		m.warnings = append(m.warnings, fmt.Sprintf("mysql cnf glob %s: %v", dir, err))
		return
	}
	sort.Strings(matches)
	for _, f := range matches {
		m.processFile(f, depth)
	}
}

func logicalMysqlCnfLines(raw string) []string {
	var out []string
	var buf strings.Builder
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		out = append(out, buf.String())
		buf.Reset()
	}
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimRight(line, "\r")
		t = strings.TrimRight(t, " \t")
		if strings.HasSuffix(t, `\`) && len(t) > 1 {
			buf.WriteString(strings.TrimSuffix(t, `\`))
			buf.WriteByte(' ')
			continue
		}
		if buf.Len() > 0 {
			buf.WriteString(t)
			flush()
			continue
		}
		out = append(out, t)
	}
	flush()
	return out
}

func mysqlStandardConfigEntryPoints() []string {
	var roots []string
	for _, p := range []string{"/etc/my.cnf", "/etc/mysql/my.cnf"} {
		if shared.FileExistsRegular(p) {
			roots = append(roots, p)
		}
	}
	for _, g := range []string{"/etc/mysql/conf.d/*.cnf", "/etc/mysql/mysql.conf.d/*.cnf", "/etc/mysql/mariadb.conf.d/*.cnf", "/etc/my.cnf.d/*.cnf"} {
		matches, _ := filepath.Glob(g)
		sort.Strings(matches)
		roots = append(roots, matches...)
	}
	return roots
}

func mysqlResolveConfigRoots(defaultsFileFromProc string, warnings *[]string) []string {
	d := strings.TrimSpace(defaultsFileFromProc)
	if d != "" {
		if shared.FileExistsRegular(d) {
			return []string{d}
		}
		*warnings = append(*warnings, "mysqld defaults-file from process not found on disk: "+d)
	}
	return mysqlStandardConfigEntryPoints()
}

func tryReadRootMyCnfPasswordExposure() (exposed bool, warn string) {
	const p = "/root/.my.cnf"
	b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return false, "cannot read /root/.my.cnf: " + err.Error()
	}
	section := ""
	for _, rawLine := range logicalMysqlCnfLines(string(b)) {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if sm := reMysqlCnfSection.FindStringSubmatch(line); len(sm) == 2 {
			section = sm[1]
			continue
		}
		if isMysqlClientSection(section) && reMysqlPasswordLine.MatchString(line) {
			return true, ""
		}
	}
	return false, ""
}

func mysqlOptsPluginLoadText(opts map[string]string) string {
	var b strings.Builder
	for _, k := range []string{"plugin_load", "plugin_load_add", "early_plugin_load"} {
		if v := strings.TrimSpace(opts[k]); v != "" {
			b.WriteString(v)
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func mysqlInferPasswordPolicyPlugin(opts map[string]string) *bool {
	s := strings.ToLower(mysqlOptsPluginLoadText(opts))
	if s == "" {
		return nil
	}
	if strings.Contains(s, "validate_password") || strings.Contains(s, "validate-password") {
		return shared.BoolPtr(true)
	}
	return shared.BoolPtr(false)
}

func mysqlInferKeyringPlugin(opts map[string]string) *bool {
	s := strings.ToLower(mysqlOptsPluginLoadText(opts))
	if s == "" {
		return nil
	}
	if strings.Contains(s, "keyring_") {
		return shared.BoolPtr(true)
	}
	return shared.BoolPtr(false)
}

func mysqlCnfBoolishPtr(v string) *bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		t := true
		return &t
	}
	if s == "0" || s == "false" || s == "off" || s == "no" {
		f := false
		return &f
	}
	t := true
	return &t
}

func mysqlBindImpliesAllInterfaces(bind string) bool {
	b := strings.ToLower(strings.TrimSpace(strings.Trim(bind, `"'`)))
	switch b {
	case "0.0.0.0", "::", "*":
		return true
	default:
		return false
	}
}

func parseMysqlPortInt(portStr string) *int {
	p := strings.TrimSpace(portStr)
	if p == "" {
		return nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return nil
	}
	return &n
}
