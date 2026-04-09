//go:build linux

package logging

import (
	"regexp"
	"strings"
)

var (
	reRsyslogTCPRemote = regexp.MustCompile(`@@([a-zA-Z0-9][a-zA-Z0-9._-]*)`)
	reRsyslogUDPRemote = regexp.MustCompile(`(?:^|[\s,;])(@)([a-zA-Z0-9][a-zA-Z0-9._-]*)(?::\d+)?(?:\s|$)`)
	reOmFwdTarget      = regexp.MustCompile(`(?i)target\s*=\s*"([^"]+)"`)
	reSyslogNgHost     = regexp.MustCompile(`(?i)(?:tcp|udp)\s*\(\s*"([^"]+)"`)
	reMetalogForward   = regexp.MustCompile(`(?i)(?:remote|host)\s*=\s*([a-zA-Z0-9][a-zA-Z0-9._-]*)`)
)

func extractRemoteLogHostsFromRsyslogLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	var out []string
	for _, m := range reRsyslogTCPRemote.FindAllStringSubmatch(line, -1) {
		if len(m) > 1 && isRemoteLogHostToken(m[1]) {
			out = append(out, m[1])
		}
	}
	for _, m := range reRsyslogUDPRemote.FindAllStringSubmatch(line, -1) {
		if len(m) > 2 && isRemoteLogHostToken(m[2]) {
			out = append(out, m[2])
		}
	}
	for _, m := range reOmFwdTarget.FindAllStringSubmatch(line, -1) {
		if len(m) > 1 {
			host := strings.TrimSpace(m[1])
			if i := strings.Index(host, ":"); i > 0 {
				host = host[:i]
			}
			if isRemoteLogHostToken(host) {
				out = append(out, host)
			}
		}
	}
	return out
}

func extractRemoteLogHostsFromSyslogNgLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	var out []string
	for _, m := range reSyslogNgHost.FindAllStringSubmatch(line, -1) {
		if len(m) > 1 {
			host := strings.TrimSpace(m[1])
			if i := strings.Index(host, ":"); i > 0 {
				host = host[:i]
			}
			if isRemoteLogHostToken(host) {
				out = append(out, host)
			}
		}
	}
	return out
}

func extractRemoteLogHostsFromMetalogLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	var out []string
	for _, m := range reMetalogForward.FindAllStringSubmatch(line, -1) {
		if len(m) > 1 && isRemoteLogHostToken(m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

func isRemoteLogHostToken(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.Contains(s, "/") || strings.Contains(s, "%") {
		return false
	}
	lower := strings.ToLower(s)
	switch lower {
	case "localhost", "0.0.0.0", "::", "::1", "127.0.0.1":
		return false
	}
	if isNumericIPToken(lower) {
		return false
	}
	return true
}

func isNumericIPToken(s string) bool {
	if strings.Count(s, ".") == 3 {
		ok := true
		for _, p := range strings.Split(s, ".") {
			if p == "" {
				ok = false
				break
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
		}
		if ok {
			return true
		}
	}
	if strings.Contains(s, ":") && !strings.Contains(s, ".") {
		hexish := true
		for _, c := range s {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':' {
				continue
			}
			hexish = false
			break
		}
		if hexish && strings.Count(s, ":") >= 2 {
			return true
		}
	}
	return false
}
