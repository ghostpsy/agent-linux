//go:build linux

package identity

import (
	"context"
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

// Capped sample rows; no account names or home directories (PII) in the payload.
const maxUserSample = 16

func minHumanUID() int {
	return 1000
}

func isNologinShell(sh string) bool {
	sh = strings.TrimSpace(strings.ToLower(sh))
	if sh == "" {
		return true
	}
	base := filepath.Base(sh)
	switch base {
	case "nologin", "false", "true", "git-shell":
		return true
	default:
		return strings.Contains(sh, "nologin")
	}
}

type passwdEnt struct {
	name, shell, home string
	uid, gid          int
}

// CollectHostUsersSummary parses /etc/passwd for counts and a capped sample (no password material).
func CollectHostUsersSummary(ctx context.Context) *payload.HostUsersSummary {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return &payload.HostUsersSummary{Error: shared.CollectionNote("/etc/passwd could not be read.")}
	}
	defer func() { _ = f.Close() }()
	var ents []passwdEnt
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			continue
		}
		ents = append(ents, passwdEnt{
			name:  parts[0],
			shell: parts[6],
			home:  parts[5],
			uid:   uid,
			gid:   gid,
		})
	}
	if err := sc.Err(); err != nil {
		slog.Warn("failed to read /etc/passwd completely", "error", err)
		return &payload.HostUsersSummary{Error: shared.CollectionNote("/etc/passwd could not be fully read.")}
	}
	if len(ents) == 0 {
		return &payload.HostUsersSummary{Error: shared.CollectionNote("no valid user entries were found in /etc/passwd.")}
	}
	minH := minHumanUID()
	var nZero, nHuman, nSystem, nShell int
	for _, e := range ents {
		if e.uid == 0 {
			nZero++
		}
		if e.uid >= minH {
			nHuman++
		} else if e.uid > 0 {
			nSystem++
		}
		if !isNologinShell(e.shell) {
			nShell++
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].uid < ents[j].uid })
	sample := make([]payload.UserSample, 0, maxUserSample)
	for _, e := range ents {
		if len(sample) >= maxUserSample {
			break
		}
		sample = append(sample, payload.UserSample{
			UID:   e.uid,
			GID:   e.gid,
			Shell: shared.TruncateRunes(e.shell, 256),
		})
	}
	return &payload.HostUsersSummary{
		NHuman:          nHuman,
		NSystem:         nSystem,
		NWithLoginShell: nShell,
		NUidZero:        nZero,
		Sample:          sample,
	}
}
