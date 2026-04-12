//go:build linux

package apache

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	apacheCmdTimeout   = 12 * time.Second
	apacheCmdMaxOutput = 256 << 10
)

// CollectApacheHttpdPosture runs allowlisted -v, -S, -M and bounded config analysis when an Apache server binary is found.
// On Debian/Ubuntu, commands go through apache2ctl when present so /etc/apache2/envvars is applied
// (${APACHE_RUN_DIR} etc.); bare apache2 -S fails without that environment. bin_path remains the server binary path.
// listeners should be the same-scan TCP listener snapshot (after collect_listeners) for Listen cross-checks.
// Returns nil when no Apache binary is present.
func CollectApacheHttpdPosture(ctx context.Context, services []payload.ServiceEntry, listeners []payload.Listener) *payload.ApacheHttpdPosture {
	serverBin := resolveApacheBinary()
	if serverBin == "" {
		return nil
	}
	invoke := resolveApacheInvoker(serverBin)
	return collectApacheHttpdPostureWithBinary(ctx, invoke, serverBin, services, listeners)
}

func collectApacheHttpdPostureWithBinary(ctx context.Context, invokeBin, reportBin string, services []payload.ServiceEntry, listeners []payload.Listener) *payload.ApacheHttpdPosture {
	out := &payload.ApacheHttpdPosture{Detected: true, BinPath: reportBin}
	stPtr, stWarn := apacheServiceStatePtr(ctx, services)
	out.ServiceState = stPtr

	subCtx, cancel := context.WithTimeout(ctx, apacheCmdTimeout)
	defer cancel()
	cmdV := exec.CommandContext(subCtx, invokeBin, "-v")
	vCombined, errV := cmdV.CombinedOutput()
	vTrim := strings.TrimSpace(string(truncateApacheOut(vCombined)))
	if errV == nil && vTrim != "" {
		out.Version = strPtr(parseApacheVersionLine(vTrim))
	}
	if errV != nil {
		out.Error = trimApacheErr("version: ", errV, vCombined)
	}

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
	} else {
		parsed := parseApacheSDump(sTrim)
		out.VhostsSummary = &payload.ApacheVhostsSummary{VhostCount: parsed.vhostCount, ServerNames: parsed.serverNames}
		out.ListenBindings = make([]payload.ApacheListenBinding, 0, len(parsed.listenBinds))
		for _, b := range parsed.listenBinds {
			out.ListenBindings = append(out.ListenBindings, payload.ApacheListenBinding{Bind: b.bind, Port: b.port})
		}
	}

	fillApacheHttpdSecurityPosture(ctx, invokeBin, out, listeners)
	if len(stWarn) > 0 {
		out.CollectorWarnings = append(stWarn, out.CollectorWarnings...)
	}
	finalizeApacheHttpdPostureArrays(out)
	return out
}

// finalizeApacheHttpdPostureArrays ensures slice fields marshal as [] not null (ingest schema: type array, not null).
func finalizeApacheHttpdPostureArrays(out *payload.ApacheHttpdPosture) {
	if out == nil {
		return
	}
	if out.ListenBindingDiscrepancies == nil {
		out.ListenBindingDiscrepancies = []string{}
	}
	if out.RiskyModulesLoaded == nil {
		out.RiskyModulesLoaded = []string{}
	}
	if out.ProtectiveModulesMissing == nil {
		out.ProtectiveModulesMissing = []string{}
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

func apacheServiceStatePtr(ctx context.Context, services []payload.ServiceEntry) (*string, []string) {
	s := apacheServiceState(ctx, services)
	if s == "running" || s == "stopped" {
		return &s, nil
	}
	return nil, []string{"service_state could not be determined as running or stopped from systemd inventory or systemctl is-active."}
}

func resolveApacheBinary() string {
	for _, name := range []string{"apache2", "httpd"} {
		p, err := exec.LookPath(name)
		if err == nil && p != "" && shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	for _, p := range []string{"/usr/sbin/apache2", "/usr/sbin/httpd", "/usr/local/apache2/bin/httpd"} {
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return ""
}

func resolveApacheInvoker(serverBin string) string {
	for _, name := range []string{"apache2ctl", "apachectl"} {
		p, err := exec.LookPath(name)
		if err == nil && p != "" && shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	for _, p := range []string{"/usr/sbin/apache2ctl", "/usr/sbin/apachectl"} {
		if shared.FileExistsRegular(p) {
			return filepath.Clean(p)
		}
	}
	return serverBin
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

func apacheServiceState(ctx context.Context, services []payload.ServiceEntry) string {
	want := map[string]struct{}{
		"apache2.service": {},
		"httpd.service":   {},
		"apache.service":  {},
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
	for _, unit := range []string{"apache2.service", "httpd.service", "apache.service"} {
		if st := systemdutil.SystemctlIsActiveState(ctx, unit); st == "running" || st == "stopped" {
			return st
		}
	}
	return ""
}
