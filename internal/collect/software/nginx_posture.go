//go:build linux

package software

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	nginxCmdTimeout   = 18 * time.Second
	nginxCmdMaxOutput = 768 << 10
)

// CollectNginxPosture runs allowlisted nginx -v, -V, and -T when a binary is found.
// Returns nil when no nginx binary is present. Omits raw configuration text; denylisted lines are skipped.
func CollectNginxPosture(ctx context.Context, services []payload.ServiceEntry) *payload.NginxPosture {
	bin := resolveNginxBinary()
	if bin == "" {
		return nil
	}
	out := &payload.NginxPosture{
		Detected:     true,
		BinPath:      bin,
		ServiceState: nginxServiceStateFromInventory(ctx, services),
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
	out.Version = parseNginxVersionLine(vTrim)

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
	} else {
		if mods := parseNginxSecurityRelevantModules(bigVTrim); len(mods) > 0 {
			out.ModulesSample = mods
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
	analysis := parseNginxTestDump(tText)
	out.SiteMapSummary = &payload.NginxSiteMapSummary{
		ServerBlockCount: analysis.serverBlockCount,
		ServerNames:      analysis.serverNames,
	}
	if len(analysis.listenKeys) > 0 {
		out.ListenBindings = make([]payload.NginxListenBinding, 0, len(analysis.listenKeys))
		for _, k := range analysis.listenKeys {
			out.ListenBindings = append(out.ListenBindings, payload.NginxListenBinding{
				Bind: k.bind,
				Port: k.port,
				SSL:  k.ssl,
			})
		}
	}
	h := buildNginxHardeningPayload(analysis.hardening)
	if h != nil {
		out.HardeningHints = h
	}
	return out
}

func buildNginxHardeningPayload(a nginxHardeningAnalysis) *payload.NginxHardeningHints {
	h := &payload.NginxHardeningHints{
		RateLimitingPresent:       a.rateLimitingSeen,
		ClientBufferLimitsPresent: a.clientLimitsSeen,
		AutoindexOnSeen:           a.autoindexOnSeen,
		HttpMethodRestrictionSeen: a.httpMethodRestrictSeen,
	}
	h.ServerTokensSummary = summarizeServerTokens(a.serverTokensModes)
	tlsSum, leg := summarizeTlsProtocols(a.sslProtocolTokens)
	h.TlsProtocolsSummary = tlsSum
	h.TlsLegacyProtocolsPresent = leg
	h.SslPreferServerCiphersSummary = summarizeBoolModes(a.sslPreferModes)
	h.SslSessionTicketsSummary = summarizeBoolModes(a.sslSessionTicketModes)
	h.SslStaplingEnabled = summarizeSslStapling(a.sslStaplingModes)
	if names := securityHeaderList(a.securityHeaderNames); len(names) > 0 {
		h.SecurityHeaderNamesPresent = names
	}
	if h.ServerTokensSummary == "" && h.TlsProtocolsSummary == "" && h.SslPreferServerCiphersSummary == "" &&
		h.SslSessionTicketsSummary == "" && h.SslStaplingEnabled == nil && len(h.SecurityHeaderNamesPresent) == 0 &&
		!h.RateLimitingPresent && !h.ClientBufferLimitsPresent && !h.AutoindexOnSeen && !h.HttpMethodRestrictionSeen &&
		h.TlsLegacyProtocolsPresent == nil {
		return nil
	}
	return h
}

func resolveNginxBinary() string {
	if p, err := exec.LookPath("nginx"); err == nil && p != "" && fileExistsRegular(p) {
		return filepath.Clean(p)
	}
	for _, p := range []string{"/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/opt/nginx/sbin/nginx"} {
		if fileExistsRegular(p) {
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

func nginxServiceStateFromInventory(ctx context.Context, services []payload.ServiceEntry) string {
	want := map[string]struct{}{
		"nginx.service":     {},
		"openresty.service": {},
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := mapSystemdActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return st
		}
	}
	for _, unit := range []string{"nginx.service", "openresty.service"} {
		if st := systemctlIsActiveState(ctx, unit); st == "running" || st == "stopped" {
			return st
		}
	}
	return "unknown"
}
