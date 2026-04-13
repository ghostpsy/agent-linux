//go:build linux

package postgres

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const maxProcScan = 8000

func resolvePostgresServerBinary() string {
	if p, err := exec.LookPath("postgres"); err == nil && p != "" {
		return p
	}
	matches, _ := filepath.Glob("/usr/lib/postgresql/*/bin/postgres")
	sort.Strings(matches)
	for _, p := range matches {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	for _, p := range []string{"/usr/bin/postgres", "/usr/local/pgsql/bin/postgres"} {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func discoverPostgresqlConfPathGlob() string {
	globs := []string{
		"/etc/postgresql/*/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/postgres/data/postgresql.conf",
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		sort.Strings(matches)
		for _, p := range matches {
			if shared.FileExistsRegular(p) {
				return p
			}
		}
	}
	return ""
}

// findPostgresProcConfigHints scans /proc for postgres/postmaster and returns data_directory (-D) and config_file (-c config_file=).
func findPostgresProcConfigHints() (dataDir, configFile string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", ""
	}
	n := 0
	for _, e := range entries {
		if n >= maxProcScan {
			break
		}
		n++
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		cmdPath := filepath.Join("/proc", pid, "cmdline")
		b, err := os.ReadFile(cmdPath)
		if err != nil || len(b) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(args) == 0 {
			continue
		}
		base := strings.ToLower(filepath.Base(args[0]))
		if base != "postgres" && base != "postmaster" {
			continue
		}
		dd, cf := parsePostgresCmdlineArgs(args)
		if dd != "" || cf != "" {
			return dd, cf
		}
	}
	return "", ""
}

func parsePostgresCmdlineArgs(args []string) (dataDir, configFile string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-D" && i+1 < len(args) {
			dataDir = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "-D") && len(a) > 2 {
			dataDir = strings.TrimPrefix(a, "-D")
			continue
		}
		if a == "-c" && i+1 < len(args) {
			if kv := strings.SplitN(args[i+1], "=", 2); len(kv) == 2 {
				if strings.EqualFold(strings.TrimSpace(kv[0]), "config_file") {
					configFile = strings.TrimSpace(kv[1])
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-cconfig_file=") {
			configFile = strings.TrimPrefix(a, "-cconfig_file=")
			continue
		}
	}
	return dataDir, configFile
}
