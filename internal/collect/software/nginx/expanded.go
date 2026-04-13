//go:build linux

package nginx

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var nginxRequiredSecurityHeaderNames = []string{
	"content_security_policy",
	"x_frame_options",
	"x_content_type_options",
	"referrer_policy",
	"permissions_policy",
}

var (
	reNginxHttpOpen        = regexp.MustCompile(`(?i)^\s*http\s*\{`)
	reNginxServerOpen      = regexp.MustCompile(`(?i)^\s*server\s*\{`)
	reNginxLocationOpen    = regexp.MustCompile(`(?i)^\s*location\s+(.+?)\s*\{\s*$`)
	reNginxUpstreamOpen    = regexp.MustCompile(`(?i)^\s*upstream\s+(\S+)\s*\{`)
	reNginxStreamOpen      = regexp.MustCompile(`(?i)^\s*stream\s*\{`)
	reNginxMailOpen        = regexp.MustCompile(`(?i)^\s*mail\s*\{`)
	reNginxSslCiphers      = regexp.MustCompile(`(?i)ssl_ciphers\s+([^;]+);`)
	reNginxUserLine        = regexp.MustCompile(`(?i)^\s*user\s+([^;]+);`)
	reNginxReturnHTTPS     = regexp.MustCompile(`(?i)return\s+30[12]\s+https://`)
	reNginxRedirectHTTPS   = regexp.MustCompile(`(?i)redirect\s+https://`)
	reNginxRewriteHTTPS    = regexp.MustCompile(`(?i)rewrite\s+.*https://`)
	reNginxStubStatus      = regexp.MustCompile(`(?i)\bstub_status\b`)
	reNginxDenyAll         = regexp.MustCompile(`(?i)deny\s+all\s*;`)
	reNginxAllowLine       = regexp.MustCompile(`(?i)allow\s+`)
	reNginxAuthBasic       = regexp.MustCompile(`(?i)auth_basic\s+`)
	reNginxMoreSetServer   = regexp.MustCompile(`(?i)more_set_headers[^;]*\bServer\s*:`)
	reNginxProxyHideServer = regexp.MustCompile(`(?i)proxy_hide_header\s+Server\s*;`)
	reNginxErrorPageCodes  = regexp.MustCompile(`(?i)error_page\s+[^;]*\b(403|404|500)\b`)
	reNginxClientMaxBody   = regexp.MustCompile(`(?i)client_max_body_size\s+([^;]+);`)
	reNginxRoot            = regexp.MustCompile(`(?i)^\s*root\s+([^;]+);`)
	reNginxAlias           = regexp.MustCompile(`(?i)^\s*alias\s+([^;]+);`)
	reNginxXForwarded      = regexp.MustCompile(`(?i)proxy_set_header\s+(X-Real-IP|X-Forwarded-For|X-Forwarded-Proto)\b`)
	reNginxProxySetHost    = regexp.MustCompile(`(?i)proxy_set_header\s+Host\b`)
	reNginxProxyPassURL    = regexp.MustCompile(`(?i)proxy_pass\s+(https?://[^\s;]+)`)
	reNginxProxyIntercept  = regexp.MustCompile(`(?i)proxy_intercept_errors\s+(on|off)\s*;`)
	reWeakCipherPatterns   = regexp.MustCompile(`(?i)\b(LOW|EXPORT|DES|RC4|MD5|NULL)\b`)
)

var sensitiveNginxPathSubstrings = []string{
	"/status", "/stub_status", "/nginx_status", "/server-status",
	"/.git", "/.env", "/.htpasswd",
}

type locAccum struct {
	path         string
	anyAddHeader bool
	secHeaders   map[string]struct{}
	stubStatus   bool
	denyAll      bool
	allowSeen    bool
	authBasic    bool
	autoindexOn  bool
}

type serverAccum struct {
	listenPort80NonSSL bool
	httpsRedirect      bool
}

type ngFrame struct {
	kind      string
	openDepth int
	path      string
	loc       *locAccum
	srv       *serverAccum
}

type nginxExpanded struct {
	serverBlockCount int
	serverNames      []string
	listenKeys       []nginxListenKey
	hardening        nginxHardeningAnalysis

	sslCiphersLast      string
	hstsFromAddHeader   string
	httpToHTTPSRedirect bool
	serverHeaderHidden  bool
	errorPageCustom     bool
	limitReqConfigured  bool
	clientMaxBodyLast   string
	proxyPassSeen       bool
	upstreamBlockSeen   bool
	proxyXForwardedSeen bool
	proxyHostHeaderSeen bool
	proxyPlaintextSeen  bool
	proxyInterceptOn    bool
	proxyInterceptSeen  bool
	runUserFromConfig   string
	rootPaths           []string

	locationsDropping []string
	autoindexPaths    []string
	sensitivePaths    []string
	stubUnrestricted  *bool
	stubStatusSeen    bool
	stubStatusOpen    bool
}

func filterRiskyNginxModules(mods []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range mods {
		low := strings.ToLower(m)
		risky := strings.Contains(low, "with-debug")
		risky = risky || strings.Contains(low, "stub_status")
		risky = risky || strings.Contains(low, "dav_module") || strings.Contains(low, "http_dav")
		risky = risky || strings.Contains(low, "autoindex_module") || strings.Contains(low, "http_autoindex")
		risky = risky || strings.Contains(low, "perl_module") || strings.Contains(low, "http_perl")
		risky = risky || strings.HasPrefix(low, "--with-mail") || strings.Contains(low, "mail_ssl_module")
		if !risky {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func sslCipherLineLooksWeak(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	return reWeakCipherPatterns.MatchString(line)
}

func innermostFrameKind(stack []ngFrame) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1].kind
}

func analyzeNginxExpanded(fullText string) nginxExpanded {
	base := parseNginxTestDump(fullText)
	var ex nginxExpanded
	ex.serverBlockCount = base.serverBlockCount
	ex.serverNames = base.serverNames
	ex.listenKeys = base.listenKeys
	ex.hardening = base.hardening

	for _, line := range strings.Split(fullText, "\n") {
		t, ok := nginxLineForDirectiveParse(line)
		if !ok {
			continue
		}
		if m := reNginxSslCiphers.FindStringSubmatch(t); len(m) == 2 {
			ex.sslCiphersLast = strings.TrimSpace(m[1])
		}
		if m := reNginxUserLine.FindStringSubmatch(t); len(m) == 2 {
			fields := strings.Fields(strings.TrimSpace(m[1]))
			if len(fields) > 0 {
				u := strings.Trim(fields[0], `"'`)
				if u != "" && !strings.HasPrefix(u, "${") {
					ex.runUserFromConfig = u
				}
			}
		}
		if m := reNginxClientMaxBody.FindStringSubmatch(t); len(m) == 2 {
			ex.clientMaxBodyLast = strings.TrimSpace(strings.Trim(m[1], `"'`))
		}
		if reNginxProxyPassURL.MatchString(t) {
			ex.proxyPassSeen = true
		}
		if reNginxXForwarded.MatchString(t) {
			ex.proxyXForwardedSeen = true
		}
		if reNginxProxySetHost.MatchString(t) {
			ex.proxyHostHeaderSeen = true
		}
		if m := reNginxProxyIntercept.FindStringSubmatch(t); len(m) == 2 {
			ex.proxyInterceptSeen = true
			if strings.EqualFold(strings.TrimSpace(m[1]), "on") {
				ex.proxyInterceptOn = true
			}
		}
		if reNginxMoreSetServer.MatchString(t) || reNginxProxyHideServer.MatchString(t) {
			ex.serverHeaderHidden = true
		}
		if reNginxErrorPageCodes.MatchString(t) {
			ex.errorPageCustom = true
		}
		if reNginxLimitReqZone.MatchString(t) || reNginxLimitReq.MatchString(t) {
			ex.limitReqConfigured = true
		}
		if m := reNginxRoot.FindStringSubmatch(t); len(m) == 2 {
			p := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			if p != "" && len(ex.rootPaths) < 48 {
				ex.rootPaths = append(ex.rootPaths, p)
			}
		}
		if m := reNginxAlias.FindStringSubmatch(t); len(m) == 2 {
			p := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			if p != "" && len(ex.rootPaths) < 48 {
				ex.rootPaths = append(ex.rootPaths, p)
			}
		}
		if strings.Contains(strings.ToLower(t), "strict-transport-security") && strings.Contains(strings.ToLower(t), "add_header") {
			if m := reNginxAddHeader.FindStringSubmatch(t); len(m) == 2 && strings.EqualFold(strings.TrimSpace(m[1]), "Strict-Transport-Security") {
				idx := strings.Index(strings.ToLower(t), "strict-transport-security")
				if idx >= 0 {
					rest := t[idx:]
					if semi := strings.Index(rest, ";"); semi > 0 {
						ex.hstsFromAddHeader = strings.TrimSpace(rest[:semi])
					} else {
						ex.hstsFromAddHeader = strings.TrimSpace(rest)
					}
					if len(ex.hstsFromAddHeader) > 512 {
						ex.hstsFromAddHeader = ex.hstsFromAddHeader[:512]
					}
				}
			}
		}
	}

	ex.proxyPlaintextSeen = evalProxyPlaintext(fullText)
	walkNginxBlocks(&ex, fullText)
	if !ex.stubStatusSeen {
		ex.stubUnrestricted = nil
	} else {
		b := ex.stubStatusOpen
		ex.stubUnrestricted = &b
	}
	ex.sensitivePaths = append(ex.sensitivePaths, sensitivePathsFromRoots(ex.rootPaths)...)
	ex.sensitivePaths = dedupeSortedStrings(ex.sensitivePaths)
	ex.autoindexPaths = dedupeSortedStrings(ex.autoindexPaths)
	ex.locationsDropping = dedupeSortedStrings(ex.locationsDropping)
	return ex
}

func sensitivePathsFromRoots(roots []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, r := range roots {
		low := strings.ToLower(r)
		for _, sub := range sensitiveNginxPathSubstrings {
			if strings.Contains(low, strings.TrimPrefix(sub, "/")) {
				key := r + ":" + sub
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func walkNginxBlocks(ex *nginxExpanded, fullText string) {
	depth := 0
	var stack []ngFrame
	var httpSec map[string]struct{}
	var serverSec map[string]struct{}

	finalizeLoc := func(loc *locAccum) {
		if loc == nil {
			return
		}
		if loc.autoindexOn && loc.path != "" {
			ex.autoindexPaths = append(ex.autoindexPaths, loc.path)
		}
		lp := strings.ToLower(loc.path)
		for _, sub := range sensitiveNginxPathSubstrings {
			s := strings.TrimPrefix(sub, "/")
			if strings.Contains(lp, s) {
				restricted := loc.denyAll || loc.authBasic || loc.allowSeen
				if !restricted {
					ex.sensitivePaths = append(ex.sensitivePaths, loc.path)
				}
				break
			}
		}
		if loc.stubStatus {
			ex.stubStatusSeen = true
			restricted := loc.denyAll || loc.authBasic || loc.allowSeen
			if !restricted {
				ex.stubStatusOpen = true
			}
		}
		if loc.anyAddHeader {
			missingAny := false
			for _, req := range nginxRequiredSecurityHeaderNames {
				if _, ok := loc.secHeaders[req]; !ok {
					missingAny = true
					break
				}
			}
			if missingAny {
				ex.locationsDropping = append(ex.locationsDropping, loc.path)
			}
		}
	}

	lines := strings.Split(fullText, "\n")
	for _, raw := range lines {
		t, ok := nginxLineForDirectiveParse(raw)
		if !ok {
			continue
		}
		applyNginxScopedLine(t, stack, httpSec, serverSec)

		opens := strings.Count(t, "{")
		closes := strings.Count(t, "}")
		openDepth := depth + opens

		if opens > 0 {
			switch {
			case reNginxHttpOpen.MatchString(t):
				httpSec = make(map[string]struct{})
				stack = append(stack, ngFrame{kind: "http", openDepth: openDepth})
			case reNginxStreamOpen.MatchString(t) || reNginxMailOpen.MatchString(t):
				stack = append(stack, ngFrame{kind: "other", openDepth: openDepth})
			case reNginxServerOpen.MatchString(t):
				if httpSec != nil {
					serverSec = cloneStrSet(httpSec)
				} else {
					serverSec = make(map[string]struct{})
				}
				stack = append(stack, ngFrame{kind: "server", openDepth: openDepth, srv: &serverAccum{}})
			case reNginxUpstreamOpen.MatchString(t):
				ex.upstreamBlockSeen = true
				m := reNginxUpstreamOpen.FindStringSubmatch(t)
				name := ""
				if len(m) > 1 {
					name = m[1]
				}
				stack = append(stack, ngFrame{kind: "upstream", openDepth: openDepth, path: name})
			default:
				if m := reNginxLocationOpen.FindStringSubmatch(t); len(m) == 2 {
					path := strings.TrimSpace(m[1])
					loc := &locAccum{path: path, secHeaders: make(map[string]struct{})}
					stack = append(stack, ngFrame{kind: "location", openDepth: openDepth, path: path, loc: loc})
				} else {
					stack = append(stack, ngFrame{kind: "other", openDepth: openDepth})
				}
			}
		}

		depth += opens - closes
		for len(stack) > 0 && stack[len(stack)-1].openDepth > depth {
			top := stack[len(stack)-1]
			if top.kind == "location" && top.loc != nil {
				finalizeLoc(top.loc)
			}
			if top.kind == "server" && top.srv != nil && top.srv.listenPort80NonSSL && top.srv.httpsRedirect {
				ex.httpToHTTPSRedirect = true
			}
			stack = stack[:len(stack)-1]
		}
	}
}

func cloneStrSet(m map[string]struct{}) map[string]struct{} {
	if m == nil {
		return make(map[string]struct{})
	}
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

func applyNginxScopedLine(t string, stack []ngFrame, httpSec, serverSec map[string]struct{}) {
	kind := innermostFrameKind(stack)
	var topLoc *locAccum
	var topSrv *serverAccum
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].kind == "location" && stack[i].loc != nil {
			topLoc = stack[i].loc
			break
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].kind == "server" && stack[i].srv != nil {
			topSrv = stack[i].srv
			break
		}
	}

	if m := reNginxDumpListen.FindStringSubmatch(t); len(m) == 2 && topSrv != nil {
		_, port, ssl, ok := parseListenDirective(strings.TrimSpace(m[1]))
		if ok && port == 80 && !ssl {
			topSrv.listenPort80NonSSL = true
		}
	}
	if topSrv != nil && (reNginxReturnHTTPS.MatchString(t) || reNginxRedirectHTTPS.MatchString(t) || reNginxRewriteHTTPS.MatchString(t)) {
		topSrv.httpsRedirect = true
	}

	if m := reNginxAddHeader.FindStringSubmatch(t); len(m) == 2 {
		canon := canonicalSecurityHeaderName(m[1])
		switch kind {
		case "location":
			if topLoc != nil {
				topLoc.anyAddHeader = true
				if canon != "" {
					topLoc.secHeaders[canon] = struct{}{}
				}
			}
		case "server":
			if serverSec != nil && canon != "" {
				serverSec[canon] = struct{}{}
			}
		case "http":
			if httpSec != nil && canon != "" {
				httpSec[canon] = struct{}{}
			}
		}
	}

	if topLoc != nil {
		if reNginxStubStatus.MatchString(t) {
			topLoc.stubStatus = true
		}
		if reNginxDenyAll.MatchString(t) {
			topLoc.denyAll = true
		}
		if reNginxAllowLine.MatchString(t) {
			topLoc.allowSeen = true
		}
		if reNginxAuthBasic.MatchString(t) {
			topLoc.authBasic = true
		}
		if reNginxAutoindexOn.MatchString(t) {
			topLoc.autoindexOn = true
		}
	}
}

func evalProxyPlaintext(fullText string) bool {
	for _, line := range strings.Split(fullText, "\n") {
		t, ok := nginxLineForDirectiveParse(line)
		if !ok {
			continue
		}
		if m := reNginxProxyPassURL.FindStringSubmatch(t); len(m) == 2 {
			u := strings.TrimSpace(m[1])
			if !strings.HasPrefix(strings.ToLower(u), "http://") {
				continue
			}
			pu, err := url.Parse(u)
			if err != nil {
				continue
			}
			host := strings.ToLower(strings.TrimSpace(pu.Hostname()))
			if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
				continue
			}
			return true
		}
	}
	return false
}

func missingNginxSecurityHeaders(present map[string]struct{}) []string {
	var miss []string
	for _, name := range nginxRequiredSecurityHeaderNames {
		if _, ok := present[name]; !ok {
			miss = append(miss, name)
		}
	}
	return miss
}

func globalSecurityHeadersPresent(fullText string) map[string]struct{} {
	present := make(map[string]struct{})
	for _, line := range strings.Split(fullText, "\n") {
		t, ok := nginxLineForDirectiveParse(line)
		if !ok {
			continue
		}
		if m := reNginxAddHeader.FindStringSubmatch(t); len(m) == 2 {
			if c := canonicalSecurityHeaderName(m[1]); c != "" {
				present[c] = struct{}{}
			}
		}
	}
	return present
}

func docrootWorldWritable(paths []string, warnings *[]string) *bool {
	if len(paths) == 0 {
		return nil
	}
	seenPath := make(map[string]struct{})
	anyWW := false
	found := false
	for _, p := range paths {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." {
			continue
		}
		if _, ok := seenPath[p]; ok {
			continue
		}
		seenPath[p] = struct{}{}
		st, err := os.Stat(p)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("nginx root path not stat-able %s: %v", p, err))
			continue
		}
		if !st.IsDir() {
			continue
		}
		found = true
		if st.Mode().Perm()&0o002 != 0 {
			anyWW = true
		}
	}
	if !found {
		return nil
	}
	return &anyWW
}
