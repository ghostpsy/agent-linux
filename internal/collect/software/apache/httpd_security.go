//go:build linux

package apache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	apacheWalkMaxFiles       = 96
	apacheWalkMaxTotalBytes  = 512 << 10
	apacheWalkMaxGlobHits    = 64
	apacheMaxDirBlocks       = 128
	apacheMaxPathList        = 64
	apacheMaxDocRoots        = 48
	apacheCtlMMaxOutputBytes = 128 << 10
)

var (
	reApacheIncludeLine   = regexp.MustCompile(`(?i)^\s*(IncludeOptional|Include)\s+(.+)$`)
	reApacheServerRoot    = regexp.MustCompile(`(?i)^\s*ServerRoot\s+"([^"]+)"\s*(?:#.*)?$`)
	reApacheServerRootUq  = regexp.MustCompile(`(?i)^\s*ServerRoot\s+(\S+)\s*(?:#.*)?$`)
	reApacheServerTokens  = regexp.MustCompile(`(?i)ServerTokens\s+(\S+)`)
	reApacheServerSig     = regexp.MustCompile(`(?i)ServerSignature\s+(\S+)`)
	reApacheListenLine    = regexp.MustCompile(`(?i)^\s*Listen\s+(.+)$`)
	reApacheUserLine    = regexp.MustCompile(`(?i)^\s*User\s+(\S+)\s*(?:#.*)?$`)
	reApacheTraceEnable = regexp.MustCompile(`(?i)^\s*TraceEnable\s+(\S+)\s*(?:#.*)?$`)
	reApacheSSLProtocol   = regexp.MustCompile(`(?i)^\s*SSLProtocol\s+(.+?)\s*(?:#.*)?$`)
	reApacheSSLCipher     = regexp.MustCompile(`(?i)^\s*SSLCipherSuite\s+(.+?)\s*(?:#.*)?$`)
	reApacheAllowOverride = regexp.MustCompile(`(?i)^\s*AllowOverride\s+(\S+)\s*(?:#.*)?$`)
	reApacheDocumentRoot  = regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(\S+)\s*(?:#.*)?$`)
	reApacheHeaderSet     = regexp.MustCompile(`(?i)^\s*Header\s+(?:(?:always|onsuccess)\s+)+(?:set|append|add|merge|note)\s+(\S+)`)
	reApacheHSTS          = regexp.MustCompile(`(?i)Strict-Transport-Security`)
	reApacheProxyReqOn    = regexp.MustCompile(`(?i)^\s*ProxyRequests\s+On\s*(?:#.*)?$`)
	reApacheProxyReqOff   = regexp.MustCompile(`(?i)^\s*ProxyRequests\s+Off\s*(?:#.*)?$`)
	reApacheRewriteHTTPS  = regexp.MustCompile(`(?i)https://`)
	reApacheRedirectHTTPS = regexp.MustCompile(`(?i)^\s*Redirect(?:Match|Permanent|Temp)?\s+.*https://`)
	reApacheLocationOpen  = regexp.MustCompile(`(?is)<Location\s+/server-status[^>]*>.*?(?:Require\s+all\s+granted|Allow\s+from\s+all)`)
	reApacheLocationInfo  = regexp.MustCompile(`(?is)<Location\s+/server-info[^>]*>.*?(?:Require\s+all\s+granted|Allow\s+from\s+all)`)
	reApacheLocationBal   = regexp.MustCompile(`(?is)<Location\s+/balancer-manager[^>]*>.*?(?:Require\s+all\s+granted|Allow\s+from\s+all)`)
	reApacheRequireIP     = regexp.MustCompile(`(?i)Require\s+(?:ip|host|forward-dns|expr|local)`)
	reApacheRequireDenied = regexp.MustCompile(`(?i)Require\s+all\s+denied`)
	reApacheEnvRunUser    = regexp.MustCompile(`(?i)^\s*(?:export\s+)?APACHE_RUN_USER\s*=\s*(\S+)\s*$`)
)

var apacheRequiredSecurityHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

var apacheRiskyModuleNames = []string{
	"status_module", "info_module", "cgi_module", "cgid_module",
	"dav_module", "proxy_module", "autoindex_module",
}

var apacheProtectiveModuleNames = []string{
	"ssl_module", "headers_module", "security2_module", "evasive20_module", "reqtimeout_module",
}

type apacheWalkState struct {
	merged       strings.Builder
	bytesTotal   int
	warnings     []string
	serverRoot   string
	visited      map[string]struct{}
	queued       []string
	mainPath     string
	filesRead    int
}

func fillApacheHttpdSecurityPosture(ctx context.Context, invokeBin string, out *payload.ApacheHttpdPosture, listeners []payload.Listener) {
	ensureApachePostureSlices(out)
	warn := &out.CollectorWarnings

	merged, walkWarns, _ := walkApacheConfigMerged()
	*warn = append(*warn, walkWarns...)

	loadedNames, errM := runApacheCtlM(ctx, invokeBin)
	if errM != nil {
		*warn = append(*warn, "apachectl -M / module list: "+errM.Error())
	} else {
		loaded := map[string]struct{}{}
		for _, n := range loadedNames {
			loaded[n] = struct{}{}
		}
		sslOn := apacheModuleLoaded(loaded, "ssl_module")
		out.SSLModuleLoaded = shared.BoolPtr(sslOn)
		out.RiskyModulesLoaded = apacheRiskyLoaded(loaded)
		out.ProtectiveModulesMissing = apacheProtectiveMissing(loaded)
		if sslOn {
			applyApacheTLSFromMerged(merged, out, warn)
		}
		if apacheModuleLoaded(loaded, "proxy_module") {
			out.OpenForwardProxy = shared.BoolPtr(apacheOpenForwardProxyUnrestricted(merged))
		}
	}

	applyApacheLeakageAndTrace(merged, out)
	out.SensitivePathsUnrestricted = apacheSensitivePathsUnrestricted(merged)
	analyzeApacheDirectoryBlocks(merged, out)
	out.MissingSecurityHeaders = apacheMissingSecurityHeaders(merged)
	out.RunUser = apacheResolveRunUser(merged)
	docRoots := apacheCollectDocumentRoots(merged)
	out.DocrootWorldWritable = apacheDocrootsWorldWritable(docRoots, warn)
	out.IsContainerized = shared.HostIsContainerized()

	if merged != "" {
		if apacheSSLProtocolSuggestsLegacyTLS(ptrStrOrEmpty(out.SSLProtocol)) {
			*warn = append(*warn, "SSLProtocol may allow TLS 1.0 or TLS 1.1; verify against policy.")
		}
	}

	disc := compareApacheListenVsSnapshot(parseListenDirectives(merged), listeners)
	out.ListenBindingDiscrepancies = disc
}

func ptrStrOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ensureApachePostureSlices(out *payload.ApacheHttpdPosture) {
	if out.RiskyModulesLoaded == nil {
		out.RiskyModulesLoaded = []string{}
	}
	if out.ProtectiveModulesMissing == nil {
		out.ProtectiveModulesMissing = []string{}
	}
	if out.ListenBindingDiscrepancies == nil {
		out.ListenBindingDiscrepancies = []string{}
	}
	if out.SensitivePathsUnrestricted == nil {
		out.SensitivePathsUnrestricted = []string{}
	}
	if out.IndexesEnabledPaths == nil {
		out.IndexesEnabledPaths = []string{}
	}
	if out.FollowSymlinksUnrestrictedPaths == nil {
		out.FollowSymlinksUnrestrictedPaths = []string{}
	}
	if out.AllowOverrideAllPaths == nil {
		out.AllowOverrideAllPaths = []string{}
	}
	if out.MissingSecurityHeaders == nil {
		out.MissingSecurityHeaders = []string{}
	}
	if out.CollectorWarnings == nil {
		out.CollectorWarnings = []string{}
	}
}

func walkApacheConfigMerged() (merged string, warnings []string, serverRoot string) {
	mainPath := resolveApacheMainConfigPath()
	if mainPath == "" {
		return "", []string{"apache main config file not found for Include walk"}, ""
	}
	st := &apacheWalkState{
		visited:    map[string]struct{}{},
		serverRoot: filepath.Dir(mainPath),
		mainPath:   mainPath,
	}
	st.queued = append(st.queued, mainPath)
	for len(st.queued) > 0 && st.filesRead < apacheWalkMaxFiles && st.bytesTotal < apacheWalkMaxTotalBytes {
		p := st.queued[0]
		st.queued = st.queued[1:]
		apacheEnqueueConfigFile(st, p)
	}
	return st.merged.String(), st.warnings, st.serverRoot
}

func resolveApacheMainConfigPath() string {
	for _, p := range []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/conf/httpd.conf"} {
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return ""
}

func apacheEnqueueConfigFile(st *apacheWalkState, path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = filepath.Clean(abs)
	if _, ok := st.visited[abs]; ok {
		return
	}
	b, err := shared.ReadFileBounded(abs, shared.DefaultConfigFileReadLimit)
	if err != nil {
		st.warnings = append(st.warnings, fmt.Sprintf("unreadable apache config %s: %v", abs, err))
		return
	}
	st.visited[abs] = struct{}{}
	st.filesRead++
	if st.bytesTotal+len(b) > apacheWalkMaxTotalBytes {
		st.warnings = append(st.warnings, "apache config walk stopped: total byte budget exceeded")
		return
	}
	st.bytesTotal += len(b)
	if m := reApacheServerRoot.FindStringSubmatch(string(b)); len(m) > 1 {
		st.serverRoot = strings.TrimSpace(m[1])
	} else if m := reApacheServerRootUq.FindStringSubmatch(string(b)); len(m) > 1 {
		st.serverRoot = strings.TrimSpace(m[1])
	}
	st.merged.WriteByte('\n')
	st.merged.Write(b)
	for _, line := range strings.Split(string(b), "\n") {
		trim := apacheStripConfigComment(line)
		if trim == "" {
			continue
		}
		m := reApacheIncludeLine.FindStringSubmatch(trim)
		if len(m) != 3 {
			continue
		}
		optional := strings.EqualFold(m[1], "IncludeOptional")
		pattern := strings.TrimSpace(m[2])
		pattern = strings.Trim(pattern, `"'`)
		if pattern == "" {
			continue
		}
		exp := apacheResolveIncludePattern(st.serverRoot, abs, pattern)
		matches, err := filepath.Glob(exp)
		if err != nil {
			st.warnings = append(st.warnings, fmt.Sprintf("Include glob error %s: %v", exp, err))
			continue
		}
		sort.Strings(matches)
		if len(matches) > apacheWalkMaxGlobHits {
			matches = matches[:apacheWalkMaxGlobHits]
			st.warnings = append(st.warnings, "Include glob truncated: "+exp)
		}
		if len(matches) == 0 {
			if !optional {
				st.warnings = append(st.warnings, "Include matched no files: "+exp)
			}
			continue
		}
		for _, hit := range matches {
			if st.filesRead >= apacheWalkMaxFiles {
				break
			}
			st.queued = append(st.queued, hit)
		}
	}
}

func apacheResolveIncludePattern(serverRoot, currentFile, pattern string) string {
	if filepath.IsAbs(pattern) {
		return pattern
	}
	if strings.HasPrefix(pattern, "/") {
		return pattern
	}
	rel := filepath.Join(filepath.Dir(currentFile), pattern)
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	return filepath.Join(serverRoot, pattern)
}

func apacheStripConfigComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	return line
}

func runApacheCtlM(ctx context.Context, invokeBin string) ([]string, error) {
	subCtx, cancel := context.WithTimeout(ctx, apacheCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, invokeBin, "-M")
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(truncateApacheOut(out)))
	if err != nil && s == "" {
		return nil, err
	}
	if len(s) > apacheCtlMMaxOutputBytes {
		s = s[:apacheCtlMMaxOutputBytes]
	}
	var names []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "loaded modules") {
			continue
		}
		idx := strings.IndexByte(line, '(')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 && err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func apacheModuleLoaded(loaded map[string]struct{}, name string) bool {
	_, ok := loaded[name]
	return ok
}

func apacheEvasiveFamilyLoaded(loaded map[string]struct{}) bool {
	for m := range loaded {
		low := strings.ToLower(m)
		if low == "evasive20_module" || low == "evasive24_module" || low == "evasive_module" {
			return true
		}
	}
	return false
}

func apacheRiskyLoaded(loaded map[string]struct{}) []string {
	out := make([]string, 0)
	for _, name := range apacheRiskyModuleNames {
		if apacheModuleLoaded(loaded, name) {
			out = append(out, name)
		}
	}
	return out
}

func apacheProtectiveMissing(loaded map[string]struct{}) []string {
	out := make([]string, 0)
	for _, name := range apacheProtectiveModuleNames {
		if name == "evasive20_module" {
			if !apacheEvasiveFamilyLoaded(loaded) {
				out = append(out, name)
			}
			continue
		}
		if !apacheModuleLoaded(loaded, name) {
			out = append(out, name)
		}
	}
	return out
}

func applyApacheTLSFromMerged(merged string, out *payload.ApacheHttpdPosture, warn *[]string) {
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		if trim == "" {
			continue
		}
		if m := reApacheSSLProtocol.FindStringSubmatch(trim); len(m) > 1 {
			v := truncateRunes(strings.TrimSpace(m[1]), apacheHardeningSSLProtocolMaxRunes)
			out.SSLProtocol = strPtr(v)
		}
		if m := reApacheSSLCipher.FindStringSubmatch(trim); len(m) > 1 {
			v := truncateRunes(strings.TrimSpace(m[1]), apacheHardeningSSLCipherMaxRunes)
			out.SSLCipherSuite = strPtr(v)
		}
	}
	if reApacheHSTS.MatchString(merged) {
		val := apacheExtractHSTSValue(merged)
		if val != "" {
			out.HstsHeader = strPtr(truncateRunes(val, 512))
		}
	}
	redir := reApacheRewriteHTTPS.MatchString(merged) || reApacheRedirectHTTPS.MatchString(merged)
	out.HTTPToHTTPSRedirect = shared.BoolPtr(redir)
	_ = warn
}

func apacheExtractHSTSValue(merged string) string {
	// Capture value after Strict-Transport-Security in Header directive (best-effort).
	re := regexp.MustCompile(`(?i)Strict-Transport-Security\s+([^#\n]+)`)
	if m := re.FindStringSubmatch(merged); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func applyApacheLeakageAndTrace(merged string, out *payload.ApacheHttpdPosture) {
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		if trim == "" {
			continue
		}
		if m := reApacheServerTokens.FindStringSubmatch(trim); len(m) > 1 {
			out.ServerTokens = strPtr(truncateRunes(strings.TrimSpace(m[1]), 64))
		}
		if m := reApacheServerSig.FindStringSubmatch(trim); len(m) > 1 {
			out.ServerSignature = strPtr(truncateRunes(strings.TrimSpace(m[1]), 64))
		}
		if m := reApacheTraceEnable.FindStringSubmatch(trim); len(m) > 1 {
			v := strings.ToLower(strings.TrimSpace(m[1]))
			enabled := v != "off"
			out.TraceEnabled = shared.BoolPtr(enabled)
		}
	}
	if out.TraceEnabled == nil {
		out.TraceEnabled = shared.BoolPtr(true)
	}
}

func apacheSensitivePathsUnrestricted(merged string) []string {
	paths := []string{}
	if reApacheLocationOpen.MatchString(merged) {
		paths = append(paths, "/server-status")
	}
	if reApacheLocationInfo.MatchString(merged) {
		paths = append(paths, "/server-info")
	}
	if reApacheLocationBal.MatchString(merged) {
		paths = append(paths, "/balancer-manager")
	}
	return paths
}

type apacheDirBlock struct {
	path string
	body string
}

func extractApacheDirectoryBlocks(content string) []apacheDirBlock {
	var blocks []apacheDirBlock
	lines := strings.Split(content, "\n")
	var stack [][]string
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		low := strings.ToLower(trim)
		if strings.HasPrefix(low, "<directory") && !strings.HasPrefix(low, "</directory") {
			path := apacheExtractXMLStylePath(trim, "Directory")
			stack = append(stack, []string{path, ""})
			continue
		}
		if strings.EqualFold(low, "</directory>") && len(stack) > 0 {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(blocks) < apacheMaxDirBlocks {
				blocks = append(blocks, apacheDirBlock{path: top[0], body: top[1]})
			}
			continue
		}
		if len(stack) > 0 {
			i := len(stack) - 1
			stack[i][1] += line + "\n"
		}
	}
	return blocks
}

func apacheExtractXMLStylePath(openLine, tag string) string {
	re := regexp.MustCompile(`(?i)<\s*` + tag + `\s+([^>]+)>`)
	m := re.FindStringSubmatch(openLine)
	if len(m) < 2 {
		return ""
	}
	inner := strings.TrimSpace(m[1])
	inner = strings.Trim(inner, `"'`)
	return truncateRunes(inner, 512)
}

func analyzeApacheDirectoryBlocks(merged string, out *payload.ApacheHttpdPosture) {
	for _, b := range extractApacheDirectoryBlocks(merged) {
		if b.path == "" {
			continue
		}
		lowBody := strings.ToLower(b.body)
		if strings.Contains(lowBody, "options") {
			for _, ol := range strings.Split(b.body, "\n") {
				t := apacheStripConfigComment(ol)
				lt := strings.ToLower(strings.TrimSpace(t))
				if strings.HasPrefix(lt, "options ") || strings.HasPrefix(lt, "options\t") {
					if optionsLineEnablesIndexes(t) {
						out.IndexesEnabledPaths = append(out.IndexesEnabledPaths, b.path)
					}
					if apacheOptionsFollowSymlinksUnrestricted(t) {
						out.FollowSymlinksUnrestrictedPaths = append(out.FollowSymlinksUnrestrictedPaths, b.path)
					}
				}
			}
		}
		for _, ol := range strings.Split(b.body, "\n") {
			t := apacheStripConfigComment(ol)
			if m := reApacheAllowOverride.FindStringSubmatch(t); len(m) > 1 {
				if strings.EqualFold(strings.TrimSpace(m[1]), "All") {
					out.AllowOverrideAllPaths = append(out.AllowOverrideAllPaths, b.path)
				}
			}
		}
	}
	out.IndexesEnabledPaths = apacheDedupCapPaths(out.IndexesEnabledPaths)
	out.FollowSymlinksUnrestrictedPaths = apacheDedupCapPaths(out.FollowSymlinksUnrestrictedPaths)
	out.AllowOverrideAllPaths = apacheDedupCapPaths(out.AllowOverrideAllPaths)
}

func optionsLineEnablesIndexes(line string) bool {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "options")
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(line[idx+len("options"):])
	rest = strings.TrimSpace(strings.Split(rest, "#")[0])
	fields := strings.Fields(rest)
	for _, f := range fields {
		if strings.EqualFold(f, "-Indexes") {
			return false
		}
	}
	for _, f := range fields {
		fl := strings.ToLower(f)
		if fl == "indexes" || fl == "+indexes" || fl == "all" {
			return true
		}
	}
	return false
}

func apacheOptionsFollowSymlinksUnrestricted(line string) bool {
	low := strings.ToLower(line)
	idx := strings.Index(low, "options")
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(line[idx+len("options"):])
	rest = strings.TrimSpace(strings.Split(rest, "#")[0])
	fields := strings.Fields(rest)
	hasFollow := false
	hasOwnerMatch := false
	for _, f := range fields {
		fl := strings.ToLower(f)
		if fl == "-followsymlinks" {
			return false
		}
		if fl == "followsymlinks" || fl == "+followsymlinks" || fl == "all" {
			hasFollow = true
		}
		if fl == "symlinksifownermatch" || fl == "+symlinksifownermatch" {
			hasOwnerMatch = true
		}
	}
	return hasFollow && !hasOwnerMatch
}

func apacheDedupCapPaths(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if len(out) >= apacheMaxPathList {
			break
		}
	}
	return out
}

func apacheMissingSecurityHeaders(merged string) []string {
	found := map[string]struct{}{}
	missing := []string{}
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		if m := reApacheHeaderSet.FindStringSubmatch(trim); len(m) > 1 {
			name := strings.TrimSpace(m[1])
			found[strings.ToLower(name)] = struct{}{}
		}
	}
	for _, want := range apacheRequiredSecurityHeaders {
		if _, ok := found[strings.ToLower(want)]; !ok {
			missing = append(missing, want)
		}
	}
	return missing
}

func apacheOpenForwardProxyUnrestricted(merged string) bool {
	lines := strings.Split(merged, "\n")
	for i, line := range lines {
		if !reApacheProxyReqOn.MatchString(line) {
			continue
		}
		restricted := false
		for j := i + 1; j < len(lines) && j < i+80; j++ {
			tl := strings.TrimSpace(lines[j])
			low := strings.ToLower(tl)
			if strings.HasPrefix(low, "<virtualhost") {
				break
			}
			if reApacheProxyReqOff.MatchString(tl) {
				restricted = true
				break
			}
			if reApacheRequireDenied.MatchString(tl) || reApacheRequireIP.MatchString(tl) {
				restricted = true
				break
			}
		}
		if !restricted {
			return true
		}
	}
	return false
}

func apacheSSLProtocolSuggestsLegacyTLS(s string) bool {
	if s == "" {
		return false
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "tlsv1.0") || strings.Contains(low, "tlsv1.1") {
		return true
	}
	if strings.Contains(low, "+tlsv1") && !strings.Contains(low, "-tlsv1") {
		return true
	}
	return false
}

func parseListenDirectives(merged string) []apacheListenKey {
	seen := map[apacheListenKey]struct{}{}
	var keys []apacheListenKey
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		m := reApacheListenLine.FindStringSubmatch(trim)
		if len(m) != 2 {
			continue
		}
		bind, port, ok := apacheParseListenArgument(strings.TrimSpace(m[1]))
		if !ok || len(keys) >= apacheMaxListenBindings {
			continue
		}
		k := apacheListenKey{bind: bind, port: port}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].bind != keys[j].bind {
			return keys[i].bind < keys[j].bind
		}
		return keys[i].port < keys[j].port
	})
	return keys
}

func apacheParseListenArgument(arg string) (bind string, port int, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", 0, false
	}
	fields := strings.Fields(arg)
	lastProto := ""
	for _, f := range fields {
		lf := strings.ToLower(f)
		if lf == "http" || lf == "https" || lf == "ftp" || lf == "h2" || lf == "h2c" {
			lastProto = lf
			continue
		}
		if strings.HasPrefix(f, "[") && strings.Contains(f, "]:") {
			host, portStr, err := splitHostPortBracketed(f)
			if err != nil {
				continue
			}
			p, err := strconv.Atoi(portStr)
			if err != nil || p <= 0 {
				continue
			}
			return apacheNormBind(host), p, true
		}
		if host, portStr, err := splitHostPortUnbracketed(f); err == nil {
			p, err := strconv.Atoi(portStr)
			if err != nil || p <= 0 {
				continue
			}
			if host == "" {
				return "*", p, true
			}
			return apacheNormBind(host), p, true
		}
		if p, err := strconv.Atoi(f); err == nil && p > 0 && p <= 65535 {
			return "*", p, true
		}
		_ = lastProto
	}
	return "", 0, false
}

func splitHostPortBracketed(s string) (host, port string, err error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return "", "", fmt.Errorf("missing opening bracket")
	}
	idx := strings.Index(s, "]:")
	if idx < 0 {
		return "", "", fmt.Errorf("missing closing bracket before port")
	}
	host = s[1:idx]
	port = s[idx+2:]
	return host, port, nil
}

func splitHostPortUnbracketed(s string) (host, port string, err error) {
	if !strings.Contains(s, ":") {
		return "", "", fmt.Errorf("missing colon in host port")
	}
	i := strings.LastIndex(s, ":")
	host = s[:i]
	port = s[i+1:]
	return host, port, nil
}

func apacheNormBind(b string) string {
	b = strings.TrimSpace(strings.ToLower(b))
	switch b {
	case "", "*", "0.0.0.0", "::", "[::]":
		return "*"
	}
	return b
}

func compareApacheListenVsSnapshot(configKeys []apacheListenKey, listeners []payload.Listener) []string {
	if len(configKeys) == 0 {
		return []string{}
	}
	apacheListeners := filterApacheListeners(listeners)
	if len(apacheListeners) == 0 {
		var out []string
		for _, k := range configKeys {
			out = append(out, fmt.Sprintf("Listen %s:%d has no matching apache/httpd listener in scan snapshot", k.bind, k.port))
		}
		return out
	}
	disc := []string{}
	for _, k := range configKeys {
		if !apacheListenerSnapshotHasPort(apacheListeners, k) {
			disc = append(disc, fmt.Sprintf("Listen %s:%d has no matching apache/httpd TCP listener in scan snapshot", k.bind, k.port))
		}
	}
	return disc
}

func filterApacheListeners(listeners []payload.Listener) []payload.Listener {
	var out []payload.Listener
	for _, li := range listeners {
		p := strings.ToLower(li.Process)
		if strings.Contains(p, "apache2") || strings.Contains(p, "httpd") || strings.Contains(p, "apache") {
			out = append(out, li)
		}
	}
	return out
}

func apacheListenerSnapshotHasPort(ap []payload.Listener, want apacheListenKey) bool {
	for _, li := range ap {
		if li.Port != want.port {
			continue
		}
		lb := apacheNormBind(li.Bind)
		wb := apacheNormBind(want.bind)
		if lb == "*" || wb == "*" || lb == wb {
			return true
		}
	}
	return false
}

func apacheResolveRunUser(merged string) *string {
	if u := readApacheEnvFileUser("/etc/apache2/envvars"); u != "" {
		return strPtr(u)
	}
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		if m := reApacheUserLine.FindStringSubmatch(trim); len(m) > 1 {
			v := strings.TrimSpace(m[1])
			if strings.HasPrefix(v, "${") {
				continue
			}
			return strPtr(truncateRunes(v, 64))
		}
	}
	return nil
}

func readApacheEnvFileUser(path string) string {
	b, err := shared.ReadFileBounded(path, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m := reApacheEnvRunUser.FindStringSubmatch(strings.TrimSpace(line)); len(m) > 1 {
			return strings.Trim(m[1], `"'`)
		}
	}
	return ""
}

func apacheCollectDocumentRoots(merged string) []string {
	seen := map[string]struct{}{}
	var roots []string
	for _, line := range strings.Split(merged, "\n") {
		trim := apacheStripConfigComment(line)
		if m := reApacheDocumentRoot.FindStringSubmatch(trim); len(m) > 1 {
			p := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			roots = append(roots, p)
			if len(roots) >= apacheMaxDocRoots {
				break
			}
		}
	}
	return roots
}

func apacheDocrootsWorldWritable(paths []string, warn *[]string) *bool {
	if len(paths) == 0 {
		return nil
	}
	anyWW := false
	found := false
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			*warn = append(*warn, fmt.Sprintf("document root not stat-able %s: %v", p, err))
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
	return shared.BoolPtr(anyWW)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// truncateRunes limits string length in runes (shared with legacy apache hardening tests).
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

const apacheHardeningSSLProtocolMaxRunes = 256
const apacheHardeningSSLCipherMaxRunes = 128
