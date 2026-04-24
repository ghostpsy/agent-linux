//go:build linux

package nginx

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	nginxMaxServerNames    = 48
	nginxMaxListenBindings = 64
	nginxMaxModules        = 32
	nginxTlsSummaryMaxLen  = 128
)

var (
	reNginxDumpListen            = regexp.MustCompile(`(?i)listen\s+([^;{]+);`)
	reNginxDumpServerName        = regexp.MustCompile(`(?i)server_name\s+([^;]+);`)
	reNginxDirectiveServerTokens = regexp.MustCompile(`(?i)server_tokens\s+(on|off)\s*;`)
	reNginxSslProtocols          = regexp.MustCompile(`(?i)ssl_protocols\s+([^;]+);`)
	reNginxSslPrefer             = regexp.MustCompile(`(?i)ssl_prefer_server_ciphers\s+(on|off)\s*;`)
	reNginxSslSessionTickets     = regexp.MustCompile(`(?i)ssl_session_tickets\s+(on|off)\s*;`)
	reNginxSslStapling           = regexp.MustCompile(`(?i)ssl_stapling\s+(on|off)\s*;`)
	reNginxAddHeader             = regexp.MustCompile(`(?i)add_header\s+([A-Za-z0-9-]+)`)
	reNginxAutoindexOn           = regexp.MustCompile(`(?i)autoindex\s+on\s*;`)
	reNginxLimitReqZone          = regexp.MustCompile(`(?i)limit_req_zone\s`)
	reNginxLimitReq              = regexp.MustCompile(`(?i)limit_req\s+`)
	reNginxClientLimit           = regexp.MustCompile(`(?i)(client_(?:body_buffer_size|header_buffer_size|max_body_size)|large_client_header_buffers)\s`)
	reNginxLimitExcept           = regexp.MustCompile(`(?i)limit_except\s+`)
	reNginxIfRequestMethod       = regexp.MustCompile(`(?i)if\s*\(\s*\$request_method`)
	reListenAddrPort             = regexp.MustCompile(`^(?:\[([^\]]+)\]|([0-9*.]+)):(\d+)$`)
	reListenBracketPort          = regexp.MustCompile(`^\[([^\]]+)\]:(\d+)$`)
)

// nginxLineForDirectiveParse returns the line without trailing # comment, or false when the line should be ignored.
func nginxLineForDirectiveParse(line string) (string, bool) {
	line = strings.TrimRight(line, "\r")
	base := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	if base == "" {
		return "", false
	}
	if strings.HasPrefix(base, "#") {
		return "", false
	}
	if deniedNginxTDirectiveLine(base) {
		return "", false
	}
	return base, true
}

// deniedNginxTDirectiveLine returns true when a line may carry secrets or out-of-scope paths; skip directive extraction.
func deniedNginxTDirectiveLine(line string) bool {
	low := strings.ToLower(strings.TrimSpace(line))
	if low == "" || strings.HasPrefix(low, "#") {
		return false
	}
	if strings.Contains(low, "ssl_certificate_key") {
		return true
	}
	if strings.Contains(low, "ssl_password_file") {
		return true
	}
	if strings.Contains(low, "ssl_engine") {
		return true
	}
	if strings.Contains(low, "auth_basic_user_file") {
		return true
	}
	if strings.Contains(low, "proxy_set_header") && strings.Contains(low, "authorization") {
		return true
	}
	return false
}

var reNginxVersion = regexp.MustCompile(`nginx/([\d.]+)`)

// parseNginxVersionLine extracts the clean semver from `nginx -v` combined output.
// "nginx version: nginx/1.24.0" → "1.24.0"
func parseNginxVersionLine(vOut string) string {
	m := reNginxVersion.FindStringSubmatch(vOut)
	if len(m) >= 2 {
		return m[1]
	}
	// Fallback: first non-empty line.
	first := strings.TrimSpace(vOut)
	if idx := strings.IndexByte(first, '\n'); idx >= 0 {
		first = strings.TrimSpace(first[:idx])
	}
	return first
}

// parseNginxSecurityRelevantModules extracts a capped, **security-focused** subset of `nginx -V`
// configure arguments: TLS/HTTP2/3/QUIC, auth, DAV/Perl, status/realip, gRPC, risky filters, debug builds,
// and dynamic modules (path reduced to basename only — no full build paths).
func parseNginxSecurityRelevantModules(vOut string) []string {
	lowAll := strings.ToLower(vOut)
	idx := strings.Index(lowAll, "configure arguments:")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(vOut[idx+len("configure arguments:"):])
	if rest == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var mods []string
	for _, tok := range strings.Fields(rest) {
		if len(mods) >= nginxMaxModules {
			break
		}
		low := strings.ToLower(tok)
		if strings.HasPrefix(low, "--add-dynamic-module=") {
			s := sanitizeNginxDynamicModuleToken(tok)
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			mods = append(mods, s)
			continue
		}
		if !strings.HasPrefix(low, "--with-") {
			continue
		}
		if nginxWithConfigureArgLeaksPath(low) {
			continue
		}
		if !nginxWithConfigureTokenSecurityRelevant(low) {
			continue
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		mods = append(mods, tok)
	}
	sort.Strings(mods)
	return mods
}

func sanitizeNginxDynamicModuleToken(tok string) string {
	eq := strings.Index(tok, "=")
	if eq < 0 || eq >= len(tok)-1 {
		return ""
	}
	val := strings.Trim(strings.TrimSpace(tok[eq+1:]), `"'`)
	if val == "" {
		return "--add-dynamic-module=redacted"
	}
	base := filepath.Base(val)
	if base == "." || base == "/" || base == string(filepath.Separator) {
		return "--add-dynamic-module=redacted"
	}
	return "--add-dynamic-module=" + base
}

func nginxWithConfigureArgLeaksPath(low string) bool {
	eq := strings.Index(low, "=")
	if eq < 0 {
		return false
	}
	key := low[:eq]
	switch key {
	case "--with-openssl", "--with-openssl-opt", "--with-pcre", "--with-pcre-jit", "--with-zlib", "--with-zlib-asm":
		return true
	default:
		return false
	}
}

func nginxWithConfigureTokenSecurityRelevant(low string) bool {
	if strings.HasPrefix(low, "--with-debug") {
		return true
	}
	needles := []string{
		"http_ssl", "stream_ssl", "mail_ssl",
		"http_v2", "http_v3", "http2", "http3", "spdy", "quic",
		"auth_basic", "auth_request", "secure_link",
		"dav_module", "perl_module",
		"stub_status",
		"realip",
		"grpc",
		"xslt",
		"gunzip_module", "slice_module", "addition_module", "sub_module",
		"image_filter",
		"degradation",
	}
	for _, n := range needles {
		if strings.Contains(low, n) {
			return true
		}
	}
	return false
}

type nginxListenKey struct {
	bind string
	port int
	ssl  bool
}

type nginxDumpAnalysis struct {
	serverBlockCount int
	serverNames      []string
	listenKeys       []nginxListenKey
	hardening        nginxHardeningAnalysis
}

type nginxHardeningAnalysis struct {
	serverTokensModes      []bool // true=on, false=off
	sslProtocolTokens      []string
	sslPreferModes         []bool
	sslSessionTicketModes  []bool
	sslStaplingModes       []bool
	securityHeaderNames    map[string]struct{}
	rateLimitingSeen       bool
	clientLimitsSeen       bool
	autoindexOnSeen        bool
	httpMethodRestrictSeen bool
}

// parseNginxTestDump extracts allowlisted metadata from bounded `nginx -T` text (no raw secret lines processed).
func parseNginxTestDump(fullText string) nginxDumpAnalysis {
	var out nginxDumpAnalysis
	out.hardening.securityHeaderNames = make(map[string]struct{})
	lines := strings.Split(fullText, "\n")
	serverLine := regexp.MustCompile(`^\s*server\s*\{\s*$`)
	nameSet := make(map[string]struct{})
	listenSeen := make(map[nginxListenKey]struct{})
	for _, line := range lines {
		base, ok := nginxLineForDirectiveParse(line)
		if !ok {
			continue
		}
		if serverLine.MatchString(base) {
			out.serverBlockCount++
		}
		applyNginxHardeningLine(base, &out.hardening)
		if m := reNginxDumpServerName.FindStringSubmatch(base); len(m) == 2 {
			for _, name := range strings.Fields(m[1]) {
				name = strings.Trim(name, `"'`)
				if name == "" || strings.HasPrefix(name, "~") || strings.HasPrefix(name, "$") {
					continue
				}
				if len(nameSet) >= nginxMaxServerNames {
					break
				}
				nameSet[name] = struct{}{}
			}
		}
		if m := reNginxDumpListen.FindStringSubmatch(base); len(m) == 2 {
			bind, port, ssl, lok := parseListenDirective(strings.TrimSpace(m[1]))
			if !lok || port <= 0 || port > 65535 {
				continue
			}
			k := nginxListenKey{bind: bind, port: port, ssl: ssl}
			if _, dup := listenSeen[k]; dup {
				continue
			}
			if len(listenSeen) >= nginxMaxListenBindings {
				continue
			}
			listenSeen[k] = struct{}{}
			out.listenKeys = append(out.listenKeys, k)
		}
	}
	for n := range nameSet {
		out.serverNames = append(out.serverNames, n)
	}
	out.serverNames = dedupeSortedStrings(out.serverNames)
	sort.Slice(out.listenKeys, func(i, j int) bool {
		if out.listenKeys[i].bind != out.listenKeys[j].bind {
			return out.listenKeys[i].bind < out.listenKeys[j].bind
		}
		if out.listenKeys[i].port != out.listenKeys[j].port {
			return out.listenKeys[i].port < out.listenKeys[j].port
		}
		return !out.listenKeys[i].ssl && out.listenKeys[j].ssl
	})
	return out
}

func applyNginxHardeningLine(trim string, h *nginxHardeningAnalysis) {
	if m := reNginxDirectiveServerTokens.FindStringSubmatch(trim); len(m) == 2 {
		h.serverTokensModes = append(h.serverTokensModes, strings.EqualFold(m[1], "on"))
		return
	}
	if m := reNginxSslProtocols.FindStringSubmatch(trim); len(m) == 2 {
		h.sslProtocolTokens = append(h.sslProtocolTokens, strings.Fields(m[1])...)
		return
	}
	if m := reNginxSslPrefer.FindStringSubmatch(trim); len(m) == 2 {
		h.sslPreferModes = append(h.sslPreferModes, strings.EqualFold(m[1], "on"))
		return
	}
	if m := reNginxSslSessionTickets.FindStringSubmatch(trim); len(m) == 2 {
		h.sslSessionTicketModes = append(h.sslSessionTicketModes, strings.EqualFold(m[1], "on"))
		return
	}
	if m := reNginxSslStapling.FindStringSubmatch(trim); len(m) == 2 {
		h.sslStaplingModes = append(h.sslStaplingModes, strings.EqualFold(m[1], "on"))
		return
	}
	if m := reNginxAddHeader.FindStringSubmatch(trim); len(m) == 2 {
		n := canonicalSecurityHeaderName(m[1])
		if n != "" {
			h.securityHeaderNames[n] = struct{}{}
		}
		return
	}
	if reNginxAutoindexOn.MatchString(trim) {
		h.autoindexOnSeen = true
		return
	}
	if reNginxLimitReqZone.MatchString(trim) || reNginxLimitReq.MatchString(trim) {
		h.rateLimitingSeen = true
		return
	}
	if reNginxClientLimit.MatchString(trim) {
		h.clientLimitsSeen = true
		return
	}
	if reNginxLimitExcept.MatchString(trim) || reNginxIfRequestMethod.MatchString(trim) {
		h.httpMethodRestrictSeen = true
		return
	}
}

func canonicalSecurityHeaderName(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "x-frame-options":
		return "x_frame_options"
	case "x-content-type-options":
		return "x_content_type_options"
	case "x-xss-protection":
		return "x_xss_protection"
	case "strict-transport-security":
		return "strict_transport_security"
	case "content-security-policy":
		return "content_security_policy"
	case "referrer-policy":
		return "referrer_policy"
	case "permissions-policy":
		return "permissions_policy"
	default:
		return ""
	}
}

func parseListenDirective(s string) (bind string, port int, ssl bool, ok bool) {
	low := strings.ToLower(s)
	ssl = strings.Contains(low, "ssl") || strings.Contains(low, "http2") ||
		strings.Contains(low, "http3") || strings.Contains(low, "quic")
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", 0, false, false
	}
	firstOrig := fields[0]
	if strings.HasPrefix(strings.ToLower(firstOrig), "unix:") {
		return "", 0, false, false
	}
	if p, err := strconv.Atoi(firstOrig); err == nil {
		return "*", p, ssl, true
	}
	if m := reListenBracketPort.FindStringSubmatch(firstOrig); len(m) == 3 {
		p, err := strconv.Atoi(m[2])
		if err != nil {
			return "", 0, false, false
		}
		addr := m[1]
		if addr == "::" {
			addr = "[::]"
		}
		return addr, p, ssl, true
	}
	if m := reListenAddrPort.FindStringSubmatch(firstOrig); len(m) == 4 {
		p, err := strconv.Atoi(m[3])
		if err != nil {
			return "", 0, false, false
		}
		addr := m[1]
		if addr == "" {
			addr = m[2]
		}
		if addr == "" || addr == "*" {
			addr = "*"
		}
		return addr, p, ssl, true
	}
	return "", 0, false, false
}

func dedupeSortedStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func summarizeServerTokens(modes []bool) string {
	if len(modes) == 0 {
		return ""
	}
	onC, offC := 0, 0
	for _, on := range modes {
		if on {
			onC++
		} else {
			offC++
		}
	}
	if onC > 0 && offC > 0 {
		return "mixed"
	}
	if offC > 0 {
		return "off"
	}
	return "on"
}

func summarizeBoolModes(modes []bool) string {
	if len(modes) == 0 {
		return ""
	}
	last := modes[len(modes)-1]
	if last {
		return "on"
	}
	return "off"
}

func summarizeTlsProtocols(tokens []string) (summary string, legacy *bool) {
	if len(tokens) == 0 {
		return "", nil
	}
	seen := make(map[string]struct{})
	var uniq []string
	leg := false
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
		if isLegacyTlsToken(t) {
			leg = true
		}
	}
	sort.Strings(uniq)
	if len(uniq) == 0 {
		return "", nil
	}
	s := strings.Join(uniq, " ")
	if len(s) > nginxTlsSummaryMaxLen {
		s = s[:nginxTlsSummaryMaxLen]
	}
	legacy = &leg
	return s, legacy
}

func isLegacyTlsToken(tok string) bool {
	u := strings.ToUpper(tok)
	switch u {
	case "TLSV1", "TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2":
		return true
	default:
		return false
	}
}

func summarizeSslStapling(modes []bool) *bool {
	if len(modes) == 0 {
		return nil
	}
	v := modes[len(modes)-1]
	return &v
}

func securityHeaderList(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
