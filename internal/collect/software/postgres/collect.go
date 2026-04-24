//go:build linux

package postgres

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const postgresPostureCmdTimeout = 12 * time.Second

var postgresLimitedStatic = []string{
	"actual roles and grants",
	"runtime SSL status",
	"installed extensions",
	"row-level security policies",
}

// CollectPostgresPosture collects PostgreSQL security posture without SQL (merged configs, pg_hba rules, fs/process checks).
func CollectPostgresPosture(ctx context.Context, services []payload.ServiceEntry, listeners []payload.Listener) *payload.PostgresPosture {
	bin := resolvePostgresServerBinary()
	if bin == "" {
		return nil
	}
	var warn []string
	out := &payload.PostgresPosture{
		Detected:                true,
		BinPath:                 bin,
		LimitedWithoutSQLAccess: append([]string(nil), postgresLimitedStatic...),
	}
	out.ServiceState = postgresServiceStatePtr(ctx, services)
	subCtx, cancel := context.WithTimeout(ctx, postgresPostureCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, bin, "-V")
	combined, err := cmd.CombinedOutput()
	if err != nil {
		out.Error = trimPostgresErr("version: ", err, combined)
	} else {
		line := strings.TrimSpace(string(combined))
		if i := strings.Index(line, "\n"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out.Version = shared.StringPtr(parsePostgresVersion(line))
		}
	}
	dataProc, cfProc := findPostgresProcConfigHints()
	startConf := pickStartConfPath(dataProc, cfProc)
	confDir := ""
	if startConf != "" {
		confDir = filepath.Dir(startConf)
	}
	if startConf == "" {
		warn = append(warn, "postgresql.conf not found (proc hints and common paths)")
	}
	settings, primary, wConf := mergePostgresqlConf(startConf)
	warn = append(warn, wConf...)
	if primary != "" {
		out.ConfigFilePath = shared.StringPtr(primary)
		out.ConfigFilePermissions = filePermissionSummary(primary)
		confDir = filepath.Dir(primary)
	}
	if len(settings) == 0 && startConf != "" {
		warn = append(warn, "postgresql.conf produced no settings (unreadable or empty includes)")
	}
	dataDir := ""
	if len(settings) > 0 {
		dataDir = resolveDataDirectory(settings, confDir)
	}
	if dataDir == "" && dataProc != "" {
		dataDir = filepath.Clean(dataProc)
	}
	if dataDir != "" {
		out.DataDirectory = shared.StringPtr(dataDir)
		out.DatadirPermissions = filePermissionSummary(dataDir)
	}
	if len(settings) > 0 {
		fillFromPostgresqlSettings(out, settings, confDir, dataDir)
	}
	hbaAbs := ""
	if len(settings) > 0 {
		hbaAbs = resolveHbaPath(settings, dataDir, confDir)
	}
	if hbaAbs == "" && startConf != "" {
		candidate := filepath.Join(filepath.Dir(startConf), "pg_hba.conf")
		if shared.FileExistsRegular(candidate) {
			hbaAbs = candidate
		}
	}
	if hbaAbs != "" {
		out.PgHbaFilePath = shared.StringPtr(hbaAbs)
		out.PgHbaPermissions = filePermissionSummary(hbaAbs)
		if b, err := shared.ReadFileBounded(hbaAbs, shared.DefaultConfigFileReadLimit); err == nil {
			ho := hbaAnalyze(string(b))
			applyHbaOutcome(out, ho)
			if ho.truncated {
				warn = append(warn, "pg_hba.conf scan truncated at line cap")
			}
		} else {
			warn = append(warn, fmt.Sprintf("pg_hba.conf unreadable: %v", err))
		}
	}
	effPort := 5432
	if out.Port != nil {
		effPort = *out.Port
	}
	if disc := postgresPortListenerDiscrepancies(effPort, listeners); len(disc) > 0 {
		out.PortListenerDiscrepancies = disc
	}
	if u := postgresRunUser(ctx); u != nil {
		out.RunUser = u
	}
	out.IsContainerized = shared.HostIsContainerized()
	if len(warn) > 0 {
		out.CollectorWarnings = sortDedupStrings(warn)
	}
	return out
}

func sortDedupStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func pickStartConfPath(dataDir, configFile string) string {
	if configFile != "" {
		cf := filepath.Clean(configFile)
		if shared.FileExistsRegular(cf) {
			return cf
		}
	}
	if dataDir != "" {
		p := filepath.Join(filepath.Clean(dataDir), "postgresql.conf")
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return discoverPostgresqlConfPathGlob()
}

func fillFromPostgresqlSettings(out *payload.PostgresPosture, settings map[string]string, confDir, dataDir string) {
	if la := settingString(settings, "listen_addresses"); la != nil {
		out.ListenAddresses = la
		t := listenAddressesImpliesAll(*la)
		out.ListenImpliesAllAddresses = &t
	}
	out.Port = settingInt(settings, "port")
	out.Ssl = settingString(settings, "ssl")
	out.SslCertFile = settingString(settings, "ssl_cert_file")
	out.SslKeyFile = settingString(settings, "ssl_key_file")
	out.SslMinProtocolVersion = settingString(settings, "ssl_min_protocol_version")
	out.SslMinProtocolWeakOrUnset = evalSslMinProtocolWeak(out.SslMinProtocolVersion)
	if c := settingString(settings, "ssl_ciphers"); c != nil {
		out.SslCiphers = c
		out.SslCiphersWeakPatterns = evalSslCiphersWeak(c)
	}
	if out.SslKeyFile != nil && strings.TrimSpace(*out.SslKeyFile) != "" {
		kp := resolveDataRelativePath(confDir, dataDir, strings.TrimSpace(*out.SslKeyFile))
		if kp != "" && shared.FileExistsRegular(kp) {
			out.SslKeyPermissions = filePermissionSummary(kp)
		}
	}
	out.LogConnections = settingString(settings, "log_connections")
	out.LogDisconnections = settingString(settings, "log_disconnections")
	out.LogStatement = settingString(settings, "log_statement")
	out.PasswordEncryption = settingString(settings, "password_encryption")
	out.PasswordEncryptionWeakMd5 = evalPasswordEncryptionWeakMd5(out.PasswordEncryption)
	out.SharedPreloadLibraries = settingString(settings, "shared_preload_libraries")
	out.PreloadAuditTrailPresent = evalPreloadAuditTrail(out.SharedPreloadLibraries)
	out.MaxConnections = settingInt(settings, "max_connections")
	out.SuperuserReservedConnections = settingInt(settings, "superuser_reserved_connections")
	out.TcpKeepalivesIdle = settingString(settings, "tcp_keepalives_idle")
	out.StatementTimeout = settingString(settings, "statement_timeout")
	out.IdleInTransactionSessionTimeout = settingString(settings, "idle_in_transaction_session_timeout")
}

func resolveDataRelativePath(confDir, dataDir, val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	if filepath.IsAbs(val) {
		return filepath.Clean(val)
	}
	if dataDir != "" {
		return filepath.Clean(filepath.Join(dataDir, val))
	}
	return filepath.Clean(filepath.Join(confDir, val))
}

func applyHbaOutcome(out *payload.PostgresPosture, ho hbaOutcome) {
	ls := ho.linesScanned
	out.HbaLinesScanned = &ls
	out.HostRuleCount = shared.IntPtr(ho.host)
	out.HostsslRuleCount = shared.IntPtr(ho.hostssl)
	out.HostnosslRulesCount = shared.IntPtr(ho.hostnossl)
	out.LocalRuleCount = shared.IntPtr(ho.localN)
	out.RejectMethodCount = shared.IntPtr(ho.rejectN)
	out.PeerOrIdentMethodCount = shared.IntPtr(ho.peerIdentN)
	out.Md5RulesCount = shared.IntPtr(ho.md5N)
	out.ScramSha256RulesCount = shared.IntPtr(ho.scramN)
	if ho.ruleOrderRisk {
		out.RuleOrderRisk = shared.BoolPtr(true)
	}
	if len(ho.trustLines) > 0 {
		out.TrustRules = ho.trustLines
	}
	if len(ho.passwordCleartextLines) > 0 {
		out.PasswordCleartextRules = ho.passwordCleartextLines
	}
	if len(ho.wideOpenLines) > 0 {
		out.WideOpenRules = ho.wideOpenLines
	}
}

func postgresPortListenerDiscrepancies(port int, listeners []payload.Listener) []string {
	if len(listeners) == 0 {
		return nil
	}
	for _, li := range listeners {
		if li.Port != port {
			continue
		}
		p := strings.ToLower(li.Process)
		if strings.Contains(p, "postgres") || strings.Contains(p, "postmaster") {
			return nil
		}
	}
	return []string{fmt.Sprintf("configured/effective port %d has no postgres/postmaster listener in scan snapshot", port)}
}

func listenAddressesImpliesAll(listen string) bool {
	for _, seg := range strings.Split(listen, ",") {
		t := strings.TrimSpace(strings.ToLower(strings.Trim(seg, `"'`)))
		if t == "*" || t == "0.0.0.0" || t == "::" || t == "all" {
			return true
		}
	}
	return false
}

func postgresServiceStatePtr(ctx context.Context, services []payload.ServiceEntry) *string {
	s := postgresServiceState(ctx, services)
	switch s {
	case "running", "stopped":
		return &s
	default:
		return nil
	}
}

func postgresServiceState(ctx context.Context, services []payload.ServiceEntry) string {
	for _, e := range services {
		if e.Name == "postgresql.service" || (strings.HasPrefix(e.Name, "postgresql@") && strings.HasSuffix(e.Name, ".service")) {
			st := systemdutil.MapActiveStateForPosture(e.ActiveState)
			if st == "running" || st == "stopped" {
				return st
			}
		}
	}
	if st := systemdutil.SystemctlIsActiveState(ctx, "postgresql.service"); st == "running" || st == "stopped" {
		return st
	}
	return "unknown"
}

func trimPostgresErr(prefix string, err error, combined []byte) string {
	msg := strings.TrimSpace(string(combined))
	if msg == "" {
		return prefix + err.Error()
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return prefix + msg
}
