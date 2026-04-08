//go:build linux

package core

import (
	"os"
	"strings"
)

const etcHostnamePath = "/etc/hostname"

// fqdnFromEtcHostname returns the first line of /etc/hostname when it looks like an FQDN.
// Many cloud images store the full name there even when nsswitch/hosts only resolve the short name.
func fqdnFromEtcHostname() string {
	return parseEtcHostnameFqdn(etcHostnamePath)
}

func parseEtcHostnameFqdn(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(string(data), "\n")
	line := strings.TrimSpace(first)
	if line == "" || !strings.Contains(line, ".") || isLocalPlaceholderFqdn(line) {
		return ""
	}
	return line
}

// resolveFqdnFromParts picks a display FQDN from hostname(1) outputs. Order: a dotted
// hostname -f, then a dotted token from hostname -A, then shortHostname + DNS domain from hostname -d.
func resolveFqdnFromParts(shortHostname, fromF, fromA, dnsDomain string) string {
	f := strings.TrimSpace(fromF)
	if f != "" && strings.Contains(f, ".") && !isLocalPlaceholderFqdn(f) {
		return f
	}
	for _, token := range strings.Fields(fromA) {
		t := strings.TrimSpace(token)
		if t != "" && strings.Contains(t, ".") && !isLocalPlaceholderFqdn(t) {
			return t
		}
	}
	d := strings.TrimSpace(dnsDomain)
	if d == "" || d == "-" || strings.EqualFold(d, "(none)") {
		return ""
	}
	short := strings.TrimSpace(shortHostname)
	if short == "" {
		return ""
	}
	return short + "." + d
}

func isLocalPlaceholderFqdn(s string) bool {
	ls := strings.ToLower(strings.TrimSpace(s))
	switch ls {
	case "localhost", "localhost.localdomain", "localhost6", "ip6-localhost", "ip6-loopback":
		return true
	default:
	}
	if strings.HasSuffix(ls, ".localhost") || strings.HasSuffix(ls, ".localdomain") {
		return true
	}
	return false
}
