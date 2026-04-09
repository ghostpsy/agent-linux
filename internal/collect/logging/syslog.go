//go:build linux

package logging

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	maxSyslogRemoteHosts        = 32
	maxForwardingSampleLines    = 8
	maxSyslogTotalReadBytes     = 256 * 1024
	maxSyslogConfigPathsTracked = 24
)

type syslogProfile struct {
	implementation string
	unitCandidates []string
	configGlob     func() []string
	parser         func(line string) []string
}

func collectSyslogForwarding() *payload.SyslogForwardingPosture {
	out := &payload.SyslogForwardingPosture{}
	profiles := []syslogProfile{
		{
			implementation: "rsyslog",
			unitCandidates: []string{"rsyslog.service", "syslog.service"},
			configGlob:     rsyslogConfigPaths,
			parser:         extractRemoteLogHostsFromRsyslogLine,
		},
		{
			implementation: "syslog_ng",
			unitCandidates: []string{"syslog-ng.service"},
			configGlob:     syslogNgConfigPaths,
			parser:         extractRemoteLogHostsFromSyslogNgLine,
		},
		{
			implementation: "metalog",
			unitCandidates: []string{"metalog.service"},
			configGlob:     metalogConfigPaths,
			parser:         extractRemoteLogHostsFromMetalogLine,
		},
	}
	for _, prof := range profiles {
		activeStr := systemdIsActiveFirst(prof.unitCandidates)
		paths := prof.configGlob()
		if len(paths) == 0 && activeStr == "" {
			continue
		}
		ent := payload.SyslogDaemonEntry{Implementation: prof.implementation}
		ent.UnitActive = unitActiveBoolFromString(activeStr)
		if activeStr != "" && len(prof.unitCandidates) > 0 {
			ent.UnitName = prof.unitCandidates[0]
		}
		var hosts []string
		var samples []string
		seenHost := map[string]struct{}{}
		bytesBudget := maxSyslogTotalReadBytes
		for _, p := range paths {
			if bytesBudget <= 0 {
				break
			}
			if len(ent.ConfigPathsRead) >= maxSyslogConfigPathsTracked {
				break
			}
			data, err := readFileBounded(p)
			if err != nil {
				continue
			}
			ent.ConfigPathsRead = append(ent.ConfigPathsRead, p)
			n := len(data)
			if n > bytesBudget {
				data = data[:bytesBudget]
				n = bytesBudget
			}
			bytesBudget -= n
			for _, line := range strings.Split(string(data), "\n") {
				for _, h := range prof.parser(line) {
					if _, dup := seenHost[h]; dup {
						continue
					}
					if len(hosts) < maxSyslogRemoteHosts {
						seenHost[h] = struct{}{}
						hosts = append(hosts, h)
					}
				}
				if len(samples) < maxForwardingSampleLines && lineLooksLikeForwardRule(line, prof.implementation) {
					samples = append(samples, shared.TruncateRunes(strings.TrimSpace(line), 512))
				}
			}
		}
		sort.Strings(hosts)
		ent.RemoteLogHosts = hosts
		ent.ForwardingRuleSampleLines = samples
		if ent.UnitActive == nil && len(ent.ConfigPathsRead) == 0 && len(hosts) == 0 {
			continue
		}
		out.Daemons = append(out.Daemons, ent)
	}
	return out
}

func rsyslogConfigPaths() []string {
	var out []string
	if st, err := os.Stat("/etc/rsyslog.conf"); err == nil && !st.IsDir() {
		out = append(out, "/etc/rsyslog.conf")
	}
	if matches, err := filepath.Glob("/etc/rsyslog.d/*.conf"); err == nil {
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out
}

func syslogNgConfigPaths() []string {
	var out []string
	for _, p := range []string{"/etc/syslog-ng/syslog-ng.conf"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			out = append(out, p)
		}
	}
	if matches, err := filepath.Glob("/etc/syslog-ng/conf.d/*.conf"); err == nil {
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out
}

func metalogConfigPaths() []string {
	if st, err := os.Stat("/etc/metalog/metalog.conf"); err == nil && !st.IsDir() {
		return []string{"/etc/metalog/metalog.conf"}
	}
	return nil
}

func lineLooksLikeForwardRule(line, impl string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	switch impl {
	case "rsyslog":
		return strings.Contains(t, "@@") || strings.Contains(t, "omfwd") || (strings.Contains(t, "@") && strings.Contains(t, "*"))
	case "syslog_ng":
		return strings.Contains(strings.ToLower(t), "tcp(") || strings.Contains(strings.ToLower(t), "udp(")
	case "metalog":
		return strings.Contains(strings.ToLower(t), "remote") || strings.Contains(strings.ToLower(t), "host")
	default:
		return false
	}
}
