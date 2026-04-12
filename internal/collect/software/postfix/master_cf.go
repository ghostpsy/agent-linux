//go:build linux

package postfix

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const masterCfMaxBytes = 96 << 10

type masterCfInsights struct {
	SubmissionPortEnabled *bool
	ShowqServiceExposed   *bool
	ChrootRatioSummary    *string
}

func resolveMasterCfPath(vals map[string]string) string {
	if cd := strings.TrimSpace(vals["config_directory"]); cd != "" {
		p := filepath.Join(cd, "master.cf")
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	for _, p := range []string{"/etc/postfix/master.cf", "/usr/local/etc/postfix/master.cf"} {
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return ""
}

func collectMasterCfInsights(masterPath string, warnings *[]string) masterCfInsights {
	out := masterCfInsights{}
	if masterPath == "" {
		*warnings = append(*warnings, "postfix master.cf path not resolved (config_directory missing or file absent)")
		return out
	}
	b, err := shared.ReadFileBounded(masterPath, masterCfMaxBytes)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("master.cf unreadable %s: %v", masterPath, err))
		return out
	}
	lines := LogicalMasterCfLines(string(b))
	var submission, smtps bool
	var showqSeen bool
	var showqInet bool
	totalSvcs := 0
	chrooted := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		svc := strings.ToLower(fields[0])
		typ := strings.ToLower(fields[1])
		if typ != "inet" && typ != "unix" && typ != "fifo" && typ != "pass" {
			continue
		}
		chrootCol := fields[4]
		totalSvcs++
		if chrootCol == "y" || chrootCol == "Y" {
			chrooted++
		}
		switch svc {
		case "submission":
			if typ == "inet" {
				submission = true
			}
		case "smtps":
			if typ == "inet" {
				smtps = true
			}
		case "showq":
			showqSeen = true
			if typ == "inet" {
				showqInet = true
			}
		}
	}
	if submission || smtps {
		out.SubmissionPortEnabled = shared.BoolPtr(true)
	} else {
		out.SubmissionPortEnabled = shared.BoolPtr(false)
	}
	if showqSeen {
		out.ShowqServiceExposed = shared.BoolPtr(showqInet)
	}
	if totalSvcs > 0 {
		s := fmt.Sprintf("%d/%d services chrooted", chrooted, totalSvcs)
		out.ChrootRatioSummary = shared.StringPtr(s)
	}
	return out
}

// LogicalMasterCfLines merges continuation lines (leading whitespace) and drops comments/empties.
func LogicalMasterCfLines(raw string) []string {
	var out []string
	var buf strings.Builder
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		out = append(out, strings.TrimSpace(buf.String()))
		buf.Reset()
	}
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimRight(line, "\r")
		if strings.TrimSpace(t) == "" {
			flush()
			continue
		}
		trimmed := strings.TrimSpace(t)
		if strings.HasPrefix(trimmed, "#") {
			flush()
			continue
		}
		if len(t) > 0 && (t[0] == ' ' || t[0] == '\t') {
			buf.WriteByte(' ')
			buf.WriteString(trimmed)
			continue
		}
		flush()
		buf.WriteString(trimmed)
	}
	flush()
	return out
}
