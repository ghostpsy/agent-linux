//go:build linux

package core

import (
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	gopsutilproc "github.com/shirou/gopsutil/v4/process"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	processTopCPU   = 8
	processTopRSS   = 8
	processTopMax   = 16
	maxCmdlineRunes = 256
)

var minerCmdlineKeywords = []string{
	"xmrig", "stratum", "cryptonight", "minerd", "kdevtmpfsi", "kinsing",
}

type procSample struct {
	pid     int32
	name    string
	user    string
	cpu     float64
	rss     uint64
	cmdline string
}

// CollectHostProcess builds top CPU/RSS merge and interpreter / heuristic signals (M1).
func CollectHostProcess() *payload.HostProcess {
	hp := &payload.HostProcess{
		Top:     []payload.ProcessTopEntry{},
		Signals: &payload.ProcessSignals{},
	}
	procs, err := gopsutilproc.Processes()
	if err != nil {
		hp.Error = "process enumeration failed"
		return hp
	}
	for _, p := range procs {
		_, _ = p.Percent(0)
	}
	time.Sleep(200 * time.Millisecond)
	var samples []procSample
	for _, p := range procs {
		pid := p.Pid
		if pid <= 0 {
			continue
		}
		cpu, err := p.Percent(0)
		if err != nil {
			slog.Debug("process cpu sample failed", "pid", pid, "error", err)
			continue
		}
		name, _ := p.Name()
		name = strings.TrimSpace(name)
		if name == "" {
			name = "unknown"
		}
		user, _ := p.Username()
		user = strings.TrimSpace(user)
		if user == "" {
			user = "unknown"
		}
		mi, _ := p.MemoryInfo()
		var rss uint64
		if mi != nil {
			rss = mi.RSS
		}
		cmdline, _ := p.Cmdline()
		samples = append(samples, procSample{
			pid: pid, name: name, user: user, cpu: cpu, rss: rss, cmdline: cmdline,
		})
	}
	hp.Signals = countProcessSignals(samples)
	hp.Top = mergeProcessTop(samples)
	return hp
}

func countProcessSignals(samples []procSample) *payload.ProcessSignals {
	sig := &payload.ProcessSignals{}
	for _, s := range samples {
		nl := strings.ToLower(s.name)
		cl := strings.ToLower(s.cmdline)
		if strings.Contains(nl, "python") || strings.HasPrefix(strings.TrimSpace(cl), "python") {
			sig.InterpreterPython++
		}
		if strings.Contains(nl, "node") || strings.Contains(nl, "nodejs") {
			sig.InterpreterNode++
		}
		if isJavaInterpreter(nl, cl) {
			sig.InterpreterJava++
		}
		for _, kw := range minerCmdlineKeywords {
			if strings.Contains(cl, kw) {
				sig.UnknownHashWorkers++
				break
			}
		}
	}
	return sig
}

func mergeProcessTop(samples []procSample) []payload.ProcessTopEntry {
	if len(samples) == 0 {
		return nil
	}
	byCPU := append([]procSample(nil), samples...)
	sort.Slice(byCPU, func(i, j int) bool {
		if byCPU[i].cpu == byCPU[j].cpu {
			return byCPU[i].rss > byCPU[j].rss
		}
		return byCPU[i].cpu > byCPU[j].cpu
	})
	byRSS := append([]procSample(nil), samples...)
	sort.Slice(byRSS, func(i, j int) bool {
		if byRSS[i].rss == byRSS[j].rss {
			return byRSS[i].cpu > byRSS[j].cpu
		}
		return byRSS[i].rss > byRSS[j].rss
	})
	seen := make(map[int32]struct{})
	var out []payload.ProcessTopEntry
	appendOne := func(s procSample) {
		if len(out) >= processTopMax {
			return
		}
		if _, dup := seen[s.pid]; dup {
			return
		}
		seen[s.pid] = struct{}{}
		out = append(out, procSampleToEntry(s))
	}
	nCPU := processTopCPU
	if nCPU > len(byCPU) {
		nCPU = len(byCPU)
	}
	for i := 0; i < nCPU; i++ {
		appendOne(byCPU[i])
	}
	nRSS := processTopRSS
	if nRSS > len(byRSS) {
		nRSS = len(byRSS)
	}
	for i := 0; i < nRSS; i++ {
		appendOne(byRSS[i])
	}
	return out
}

func procSampleToEntry(s procSample) payload.ProcessTopEntry {
	cmd := RedactCmdline(s.cmdline)
	cmd = shared.TruncateRunes(cmd, maxCmdlineRunes)
	return payload.ProcessTopEntry{
		Pid:              s.pid,
		Name:             shared.TruncateRunes(s.name, 256),
		User:             shared.TruncateRunes(s.user, 64),
		CpuPct:           round2(s.cpu),
		RssMb:            round2(float64(s.rss) / 1048576.0),
		CmdlineTruncated: cmd,
	}
}

func round2(x float64) float64 {
	return math.Round(x*100) / 100
}

func isJavaInterpreter(nameLower, cmdLower string) bool {
	if nameLower == "java" {
		return true
	}
	t := strings.TrimSpace(cmdLower)
	return strings.HasPrefix(t, "java ")
}
