//go:build linux

package firewall

import (
	"net"
	"regexp"
	"strings"
)

var ipv4WithOptionalCIDR = regexp.MustCompile(
	`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:3[0-2]|[12]?[0-9]))?\b`,
)

// redactFirewallTelemetryLine removes shell-style comments and replaces IP literals for ingest (UFW verbose, etc.).
func redactFirewallTelemetryLine(line string) string {
	line = strings.TrimRight(line, "\r")
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") {
		return "#"
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimRight(line[:i], " \t")
	}
	line = redactIPLiteralsInString(line)
	return line
}

// redactRulesetDumpForIngest strips comment-only lines to "#", drops end-of-line comments, and redacts IPs in iptables-save / nft text.
func redactRulesetDumpForIngest(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			b.WriteString("#")
		} else {
			if j := strings.Index(line, " #"); j >= 0 {
				line = strings.TrimRight(line[:j], " \t")
			}
			line = redactIPLiteralsInString(line)
			b.WriteString(line)
		}
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func redactIPLiteralsInString(s string) string {
	s = ipv4WithOptionalCIDR.ReplaceAllString(s, "x.x.x.x")
	return redactIPv6Literals(s)
}

func redactIPv6Literals(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// Bracketed IPv6 (e.g. nft or -s [dead::1])
		if s[i] == '[' {
			end := strings.IndexByte(s[i+1:], ']')
			if end >= 0 {
				inner := s[i+1 : i+1+end]
				if ip := net.ParseIP(inner); ip != nil && ip.To4() == nil {
					b.WriteString("[x:x:x:x:x:x:x:x]")
					i += end + 2
					continue
				}
			}
			b.WriteByte('[')
			i++
			continue
		}
		// Unbracketed: longest run of hex/colon/dot/% that parses as IPv6 (incl. CIDR).
		if isIPv6TokenStart(s[i]) {
			j := i + 1
			for j < len(s) && isIPv6TokenChar(s[j]) {
				j++
			}
			tok := s[i:j]
			tokIP, tokCIDR, ok := splitIPCIDR(tok)
			if ok {
				if ip := net.ParseIP(tokIP); ip != nil && ip.To4() == nil {
					if tokCIDR != "" {
						b.WriteString("x:x:x:x:x:x:x:x/" + tokCIDR)
					} else {
						b.WriteString("x:x:x:x:x:x:x:x")
					}
					i = j
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isIPv6TokenStart(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':'
}

func isIPv6TokenChar(c byte) bool {
	return isIPv6TokenStart(c) || c == '.' || c == '%' || c == '/'
}

func splitIPCIDR(tok string) (ipPart, cidrPart string, ok bool) {
	if tok == "" {
		return "", "", false
	}
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		suffix := tok[i+1:]
		if suffix == "" {
			return tok, "", true
		}
		for _, c := range suffix {
			if c < '0' || c > '9' {
				return tok, "", true
			}
		}
		return tok[:i], suffix, true
	}
	return tok, "", true
}
