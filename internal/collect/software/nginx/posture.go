//go:build linux

package nginx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	nginxCmdTimeout   = 18 * time.Second
	nginxCmdMaxOutput = 768 << 10
	nginxPsTimeout    = 4 * time.Second
)

var (
	reNginxConfFileComment = regexp.MustCompile(`(?i)^#\s*configuration file\s+([^:]+):\s*$`)
	reNginxSyntaxConfLine  = regexp.MustCompile(`(?i)nginx:\s*the configuration file\s+(\S+)\s+syntax`)
)

// CollectNginxPosture runs allowlisted nginx -v, -V, and -T when a binary is found.
// listeners should be the same-scan TCP listener snapshot (may be empty before collect_listeners runs).
// Returns nil when no nginx binary is present. Omits raw configuration text; denylisted lines are skipped.
func CollectNginxPosture(ctx context.Context, services []payload.ServiceEntry, listeners []payload.Listener) *payload.NginxPosture {
	bin := resolveNginxBinary()
	if bin == "" {
		return nil
	}
	var collWarnings []string
	out := &payload.NginxPosture{Detected: true, BinPath: bin}
	if st := nginxServiceStatePtr(ctx, services); st != nil {
		out.ServiceState = st
	}
	subCtx, cancel := context.WithTimeout(ctx, nginxCmdTimeout)
	defer cancel()
	cmdV := exec.CommandContext(subCtx, bin, "-v")
	vCombined, errV := cmdV.CombinedOutput()
	if errV != nil {
		out.Error = trimNginxErr("version: ", errV, vCombined)
		return out
	}
	vTrim := strings.TrimSpace(string(truncateNginxOut(vCombined)))
	out.Version = nginxStrPtr(parseNginxVersionLine(vTrim))

	subCtxV, cancelV := context.WithTimeout(ctx, nginxCmdTimeout)
	defer cancelV()
	cmdBigV := exec.CommandContext(subCtxV, bin, "-V")
	bigVOut, errBigV := cmdBigV.CombinedOutput()
	bigVTrim := strings.TrimSpace(string(truncateNginxOut(bigVOut)))
	if errBigV != nil {
		if out.Error != "" {
			out.Error += "; "
		}
		out.Error += trimNginxErr("build info: ", errBigV, bigVOut)
	} else if mods := parseNginxSecurityRelevantModules(bigVTrim); len(mods) > 0 {
		out.ModulesSample = mods
		if risky := filterRiskyNginxModules(mods); len(risky) > 0 {
			out.RiskyModulesCompiled = risky
		}
	}

	subCtxT, cancelT := context.WithTimeout(ctx, nginxCmdTimeout)
	defer cancelT()
	cmdT := exec.CommandContext(subCtxT, bin, "-T")
	tCombined, errT := cmdT.CombinedOutput()
	tText := string(truncateNginxOut(tCombined))
	if errT != nil {
		if out.Error != "" {
			out.Error += "; "
		}
		out.Error += trimNginxErr("config test dump: ", errT, tCombined)
	}

	exp := analyzeNginxExpanded(tText)
	out.SiteMapSummary = &payload.NginxSiteMapSummary{ServerBlockCount: exp.serverBlockCount, ServerNames: exp.serverNames}
	if len(exp.listenKeys) > 0 {
		out.ListenBindings = make([]payload.NginxListenBinding, 0, len(exp.listenKeys))
		for _, k := range exp.listenKeys {
			out.ListenBindings = append(out.ListenBindings, payload.NginxListenBinding{Bind: k.bind, Port: k.port, SSL: k.ssl})
		}
	}
	if disc := compareNginxListenVsSnapshot(exp.listenKeys, listeners); len(disc) > 0 {
		out.ListenBindingDiscrepancies = disc
	}

	tlsSum, leg := summarizeTlsProtocols(exp.hardening.sslProtocolTokens)
	if tlsSum != "" {
		s := tlsSum
		out.SslProtocols = &s
	}
	out.TlsLegacyProtocolsPresent = leg
	if len(exp.listenKeys) > 0 {
		hasSSL := false
		for _, k := range exp.listenKeys {
			if k.ssl {
				hasSSL = true
				break
			}
		}
		b := hasSSL
		out.SslConfigured = &b
	}
	if exp.sslCiphersLast != "" {
		c := exp.sslCiphersLast
		out.SslCiphers = &c
		w := sslCipherLineLooksWeak(exp.sslCiphersLast)
		out.SslCiphersWeakPatterns = &w
	}
	if st := summarizeServerTokens(exp.hardening.serverTokensModes); st != "" {
		out.ServerTokens = &st
	}
	if sp := summarizeBoolModes(exp.hardening.sslPreferModes); sp != "" {
		out.SslPreferServerCiphers = &sp
	}
	if sst := summarizeBoolModes(exp.hardening.sslSessionTicketModes); sst != "" {
		out.SslSessionTicketsSummary = &sst
	}
	out.SslStapling = summarizeSslStapling(exp.hardening.sslStaplingModes)
	if exp.hstsFromAddHeader != "" {
		h := exp.hstsFromAddHeader
		out.HstsHeader = &h
	}
	if exp.httpToHTTPSRedirect {
		b := true
		out.HttpToHttpsRedirect = &b
	}
	out.StubStatusUnrestricted = exp.stubUnrestricted
	if exp.serverHeaderHidden {
		b := true
		out.ServerHeaderHidden = &b
	}
	if exp.errorPageCustom {
		b := true
		out.ErrorPageCustom = &b
	}
	if miss := missingNginxSecurityHeaders(globalSecurityHeadersPresent(tText)); len(miss) > 0 {
		out.MissingSecurityHeaders = miss
	}
	if len(exp.locationsDropping) > 0 {
		out.LocationsDroppingParentHeaders = exp.locationsDropping
	}
	if len(exp.autoindexPaths) > 0 {
		out.AutoindexEnabledPaths = exp.autoindexPaths
	}
	if len(exp.sensitivePaths) > 0 {
		out.SensitivePathsUnrestricted = exp.sensitivePaths
	}
	if exp.limitReqConfigured {
		b := true
		out.LimitReqConfigured = &b
	}
	if exp.clientMaxBodyLast != "" {
		s := exp.clientMaxBodyLast
		out.ClientMaxBodySize = &s
	}
	if exp.proxyPassSeen || exp.upstreamBlockSeen {
		b := true
		out.ProxyPassOrUpstreamSeen = &b
	}
	if exp.proxyXForwardedSeen {
		b := true
		out.ProxyHeadersForwarded = &b
	}
	if exp.proxyHostHeaderSeen {
		b := true
		out.ProxyHostHeader = &b
	}
	if exp.proxyPlaintextSeen {
		b := true
		out.UpstreamPlaintext = &b
	}
	if exp.proxyInterceptSeen {
		b := exp.proxyInterceptOn
		out.ProxyInterceptErrors = &b
	}
	if exp.runUserFromConfig != "" {
		u := exp.runUserFromConfig
		out.RunUser = &u
	}
	if wu := nginxWorkerRunUserNonRoot(ctx); wu != nil {
		out.RunUserWorkersNonRoot = wu
	}
	if mainPath := extractNginxMainConfigPath(tText); mainPath != "" {
		if fi, err := os.Stat(mainPath); err == nil {
			s := fmt.Sprintf("%04o", fi.Mode().Perm()&0o777)
			out.ConfigFilePermissions = &s
		} else {
			collWarnings = append(collWarnings, fmt.Sprintf("main nginx config not stat-able: %v", err))
		}
	}
	if dww := docrootWorldWritable(exp.rootPaths, &collWarnings); dww != nil {
		out.DocrootWorldWritable = dww
	}
	if ic := nginxHostContainerSignal(); ic != nil {
		out.IsContainerized = ic
	}
	if len(collWarnings) > 0 {
		sort.Strings(collWarnings)
		out.CollectorWarnings = collWarnings
	}
	return out
}

func nginxStrPtr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func extractNginxMainConfigPath(dump string) string {
	for _, line := range strings.Split(dump, "\n") {
		if m := reNginxConfFileComment.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 2 {
			p := strings.TrimSpace(m[1])
			if p != "" {
				return p
			}
		}
	}
	for _, line := range strings.Split(dump, "\n") {
		if m := reNginxSyntaxConfLine.FindStringSubmatch(line); len(m) == 2 {
			p := strings.TrimSpace(m[1])
			if p != "" {
				return p
			}
		}
	}
	return ""
}

func nginxWorkerRunUserNonRoot(ctx context.Context) *bool {
	subCtx, cancel := context.WithTimeout(ctx, nginxPsTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, "ps", "axo", "user,cmd")
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) == 0 {
		return nil
	}
	sawWorker := false
	anyRootWorker := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		cmdLine := strings.Join(parts[1:], " ")
		low := strings.ToLower(cmdLine)
		if !strings.Contains(low, "nginx:") || !strings.Contains(low, "worker") {
			continue
		}
		sawWorker = true
		if user == "root" {
			anyRootWorker = true
		}
	}
	if !sawWorker {
		return nil
	}
	b := !anyRootWorker
	return &b
}

func nginxHostContainerSignal() *bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t := true
		return &t
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return nil
	}
	s := string(data)
	if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") {
		t := true
		return &t
	}
	f := false
	return &f
}

func resolveNginxBinary() string {
	if p, err := exec.LookPath("nginx"); err == nil && p != "" && shared.FileExistsRegular(p) {
		return filepath.Clean(p)
	}
	for _, p := range []string{"/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/opt/nginx/sbin/nginx"} {
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return ""
}

func truncateNginxOut(b []byte) []byte {
	if len(b) <= nginxCmdMaxOutput {
		return b
	}
	return b[:nginxCmdMaxOutput]
}

func trimNginxErr(prefix string, err error, combined []byte) string {
	msg := strings.TrimSpace(string(truncateNginxOut(combined)))
	if msg == "" {
		return prefix + err.Error()
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return prefix + msg
}

func nginxServiceStatePtr(ctx context.Context, services []payload.ServiceEntry) *string {
	s := nginxServiceStateFromInventory(ctx, services)
	switch s {
	case "running", "stopped":
		return &s
	default:
		return nil
	}
}

func nginxServiceStateFromInventory(ctx context.Context, services []payload.ServiceEntry) string {
	want := map[string]struct{}{
		"nginx.service":     {},
		"openresty.service": {},
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := systemdutil.MapActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return st
		}
	}
	for _, unit := range []string{"nginx.service", "openresty.service"} {
		if st := systemdutil.SystemctlIsActiveState(ctx, unit); st == "running" || st == "stopped" {
			return st
		}
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "unknown"
	}
	return "unknown"
}
