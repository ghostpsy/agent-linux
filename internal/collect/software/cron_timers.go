//go:build linux

package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	maxCronSampleLines  = 12
	maxCronDropinNames  = 24
	maxUserCrontabUsers = 8
	maxUserCrontabLines = 16
	maxTimerUnitsSample = 48
	cronCollectTimeout  = 20 * time.Second
)

// CollectCronTimersInventory summarizes /etc/crontab, cron.d, user spool, and systemd timers.
func CollectCronTimersInventory() *payload.CronTimersInventory {
	out := &payload.CronTimersInventory{}
	if b, err := readFileBounded("/etc/crontab"); err == nil {
		lines := nonCommentLines(string(b))
		out.SystemCrontabLineCount = len(lines)
		out.SystemCrontabSample = capStringSlice(lines, maxCronSampleLines, 256)
	}
	dropins, _ := filepath.Glob("/etc/cron.d/*")
	sort.Strings(dropins)
	for i, p := range dropins {
		if i >= maxCronDropinNames {
			break
		}
		out.CronDropinFileNamesSample = append(out.CronDropinFileNamesSample, filepath.Base(p))
	}
	spoolDirs := []string{"/var/spool/cron/crontabs", "/var/spool/cron"}
	for _, dir := range spoolDirs {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			out.CronVarSpoolModeOctal = fmt.Sprintf("%04o", st.Mode().Perm())
			ents, _ := os.ReadDir(dir)
			var users []string
			for _, e := range ents {
				if !e.Type().IsRegular() {
					continue
				}
				name := e.Name()
				if name == "." || name == ".." {
					continue
				}
				users = append(users, name)
			}
			sort.Strings(users)
			out.UserCrontabsPresentCount = len(users)
			for i, u := range users {
				if i >= maxUserCrontabUsers {
					break
				}
				out.UserCrontabUsersSample = append(out.UserCrontabUsersSample, shared.TruncateRunes(u, 64))
			}
			var lineBuf []string
			for _, u := range users {
				if len(lineBuf) >= maxUserCrontabLines {
					break
				}
				b, err := readFileBounded(filepath.Join(dir, u))
				if err != nil {
					continue
				}
				for _, ln := range nonCommentLines(string(b)) {
					if len(lineBuf) >= maxUserCrontabLines {
						break
					}
					lineBuf = append(lineBuf, u+": "+shared.TruncateRunes(ln, 220))
				}
			}
			out.UserCrontabLinesSample = lineBuf
			break
		}
	}
	fillSystemdTimers(out)
	return out
}

func nonCommentLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

func capStringSlice(in []string, maxN, maxRunes int) []string {
	if len(in) <= maxN {
		r := make([]string, len(in))
		for i, s := range in {
			r[i] = shared.TruncateRunes(s, maxRunes)
		}
		return r
	}
	r := make([]string, maxN)
	for i := 0; i < maxN; i++ {
		r[i] = shared.TruncateRunes(in[i], maxRunes)
	}
	return r
}

func fillSystemdTimers(out *payload.CronTimersInventory) {
	ctx, cancel := context.WithTimeout(context.Background(), cronCollectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "list-timers", "--all", "--no-pager", "--output=json")
	raw, err := cmd.Output()
	if err != nil {
		tryParseSystemctlTimersText(out)
		return
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		tryParseSystemctlTimersText(out)
		return
	}
	out.SystemdTimersCount = len(rows)
	for i, row := range rows {
		if i >= maxTimerUnitsSample {
			break
		}
		u, _ := row["unit"].(string)
		if u != "" {
			out.SystemdTimerUnitsSample = append(out.SystemdTimerUnitsSample, shared.TruncateRunes(u, 128))
		}
	}
}

func tryParseSystemctlTimersText(out *payload.CronTimersInventory) {
	ctx, cancel := context.WithTimeout(context.Background(), cronCollectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "list-timers", "--all", "--no-pager", "--no-legend")
	raw, err := cmd.Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(raw), "\n")
	var units []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		unit := fields[len(fields)-2]
		if strings.HasSuffix(unit, ".timer") {
			units = append(units, unit)
		}
	}
	out.SystemdTimersCount = len(units)
	for i, u := range units {
		if i >= maxTimerUnitsSample {
			break
		}
		out.SystemdTimerUnitsSample = append(out.SystemdTimerUnitsSample, shared.TruncateRunes(u, 128))
	}
}
