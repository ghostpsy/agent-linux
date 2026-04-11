//go:build linux

package software

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	apacheCmdTimeout   = 12 * time.Second
	apacheCmdMaxOutput = 256 << 10
)

// CollectApacheHttpdPosture runs allowlisted -v and -S when an Apache server binary is found.
// On Debian/Ubuntu, commands go through apache2ctl when present so /etc/apache2/envvars is applied
// (${APACHE_RUN_DIR} etc.); bare apache2 -S fails without that environment. bin_path remains the server binary path.
// Returns nil when no Apache binary is present. serviceState is derived from services inventory.
func CollectApacheHttpdPosture(ctx context.Context, services []payload.ServiceEntry) *payload.ApacheHttpdPosture {
	serverBin := resolveApacheBinary()
	if serverBin == "" {
		return nil
	}
	invoke := resolveApacheInvoker(serverBin)
	return collectApacheHttpdPostureWithBinary(ctx, invoke, serverBin, services)
}

// collectApacheHttpdPostureWithBinary runs -v / -S against invokeBin; reportBin is stored as bin_path (tests pass the same stub for both).
func collectApacheHttpdPostureWithBinary(ctx context.Context, invokeBin, reportBin string, services []payload.ServiceEntry) *payload.ApacheHttpdPosture {
	out := &payload.ApacheHttpdPosture{
		Detected:     true,
		BinPath:      reportBin,
		ServiceState: apacheServiceStateFromInventory(services),
	}
	out.HardeningHints = collectApacheHardeningHints(ctx)
	subCtx, cancel := context.WithTimeout(ctx, apacheCmdTimeout)
	defer cancel()
	cmdV := exec.CommandContext(subCtx, invokeBin, "-v")
	vCombined, errV := cmdV.CombinedOutput()
	if errV != nil {
		out.Error = trimApacheErr("version: ", errV, vCombined)
		return out
	}
	vTrim := strings.TrimSpace(string(truncateApacheOut(vCombined)))
	out.Version = parseApacheVersionLine(vTrim)

	subCtx2, cancel2 := context.WithTimeout(ctx, apacheCmdTimeout)
	defer cancel2()
	cmdS := exec.CommandContext(subCtx2, invokeBin, "-S")
	sCombined, errS := cmdS.CombinedOutput()
	sTrim := strings.TrimSpace(string(truncateApacheOut(sCombined)))
	if errS != nil {
		if out.Error != "" {
			out.Error += "; "
		}
		out.Error += trimApacheErr("vhost dump: ", errS, sCombined)
		return out
	}
	parsed := parseApacheSDump(sTrim)
	out.VhostsSummary = &payload.ApacheVhostsSummary{
		VhostCount:  parsed.vhostCount,
		ServerNames: parsed.serverNames,
	}
	if len(parsed.listenBinds) > 0 {
		out.ListenBindings = make([]payload.ApacheListenBinding, 0, len(parsed.listenBinds))
		for _, b := range parsed.listenBinds {
			out.ListenBindings = append(out.ListenBindings, payload.ApacheListenBinding{Bind: b.bind, Port: b.port})
		}
	}
	return out
}

func resolveApacheBinary() string {
	for _, name := range []string{"apache2", "httpd"} {
		p, err := exec.LookPath(name)
		if err == nil && p != "" && fileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	for _, p := range []string{"/usr/sbin/apache2", "/usr/sbin/httpd", "/usr/local/apache2/bin/httpd"} {
		if fileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return ""
}

// resolveApacheInvoker returns apache2ctl or apachectl when on PATH or under /usr/sbin so config envvars load; otherwise serverBin.
func resolveApacheInvoker(serverBin string) string {
	for _, name := range []string{"apache2ctl", "apachectl"} {
		p, err := exec.LookPath(name)
		if err == nil && p != "" && fileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	for _, p := range []string{"/usr/sbin/apache2ctl", "/usr/sbin/apachectl"} {
		if fileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return serverBin
}

func fileExistsRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func truncateApacheOut(b []byte) []byte {
	if len(b) <= apacheCmdMaxOutput {
		return b
	}
	return b[:apacheCmdMaxOutput]
}

func trimApacheErr(prefix string, err error, combined []byte) string {
	msg := strings.TrimSpace(string(truncateApacheOut(combined)))
	if msg == "" {
		return prefix + err.Error()
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return prefix + msg
}

func apacheServiceStateFromInventory(services []payload.ServiceEntry) string {
	want := map[string]struct{}{
		"apache2.service": {},
		"httpd.service":   {},
		"apache.service":  {},
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(e.ActiveState)) {
		case "active":
			return "running"
		case "inactive", "failed":
			return "stopped"
		default:
			if e.ActiveState != "" {
				return "unknown"
			}
		}
	}
	return "unknown"
}
