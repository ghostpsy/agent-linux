//go:build linux

package logging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const ldSoPreloadPath = "/etc/ld.so.preload"

var sysstatCronPaths = []string{
	"/etc/cron.d/sysstat",
	"/etc/cron.daily/sysstat",
	"/etc/cron.hourly/sysstat",
	"/etc/cron.weekly/sysstat",
}

func collectProcessAccountingPosture() *payload.ProcessAccountingPosture {
	out := &payload.ProcessAccountingPosture{}
	if _, err := exec.LookPath("sadc"); err == nil {
		out.SadcOnPath = true
	}
	out.SysstatCronHint = scanSysstatCronHints()
	st, err := os.Stat(ldSoPreloadPath)
	if err == nil && !st.IsDir() && st.Size() > 0 {
		out.LdSoPreloadFilePresent = true
		out.LdSoPreloadPath = ldSoPreloadPath
	}
	return out
}

func scanSysstatCronHints() bool {
	for _, p := range sysstatCronPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	if b, err := readFileBounded("/etc/crontab"); err == nil {
		if strings.Contains(strings.ToLower(string(b)), "sysstat") || strings.Contains(string(b), "sadc") {
			return true
		}
	}
	if matches, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		for _, p := range matches {
			if b, err := readFileBounded(p); err == nil {
				lower := strings.ToLower(string(b))
				if strings.Contains(lower, "sysstat") || strings.Contains(lower, "sadc") {
					return true
				}
			}
		}
	}
	return false
}
