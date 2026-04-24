//go:build linux

package mysql

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const mysqlPostureCmdTimeout = 10 * time.Second

// CollectMysqlPosture collects MySQL/MariaDB security posture without SQL access. Returns nil when no server binary is found.
func CollectMysqlPosture(ctx context.Context, services []payload.ServiceEntry) *payload.MysqlPosture {
	bin, engine := resolveMysqlServerBinary()
	if bin == "" {
		return nil
	}
	var warnings []string
	limited := mysqlDefaultLimitedWithoutSQL()
	stPtr, stWarn := mysqlServiceStatePtr(ctx, services)
	if len(stWarn) > 0 {
		warnings = append(warnings, stWarn...)
	}
	out := &payload.MysqlPosture{
		Detected:                true,
		Engine:                  engine,
		BinPath:                 bin,
		ServiceState:            stPtr,
		LimitedWithoutSQLAccess: limited,
	}
	subCtx, cancel := context.WithTimeout(ctx, mysqlPostureCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, bin, "--version")
	combined, err := cmd.CombinedOutput()
	if err != nil {
		out.Error = trimMysqlPostureErr("version: ", err, combined)
	} else {
		line := strings.TrimSpace(string(combined))
		if i := strings.Index(line, "\n"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			if out.Engine == "unknown" {
				out.Engine = engineFromVersionString(line)
			}
			out.Version = shared.StringPtr(parseMysqlVersion(line))
		}
	}
	defFile := discoverMysqldDefaultsFileFromProc()
	roots := mysqlResolveConfigRoots(defFile, &warnings)
	opts, primaryPath, pwdExposed, filesRead, mergeWarn := mergeMysqlMysqldOptions(roots)
	warnings = append(warnings, mergeWarn...)
	rootPwd, rootWarn := tryReadRootMyCnfPasswordExposure()
	if rootWarn != "" {
		warnings = append(warnings, rootWarn)
	}
	if rootPwd {
		pwdExposed = true
	}
	applyMysqlOptsToPosture(opts, filesRead, primaryPath, pwdExposed, ctx, &warnings, out)
	out.CollectorWarnings = append(warnings, out.CollectorWarnings...)
	finalizeMysqlPostureArrays(out)
	return out
}

func mysqlDefaultLimitedWithoutSQL() []string {
	return []string{
		"User accounts, roles, and privileges (requires SQL access)",
		"Runtime TLS negotiation state (requires a live connection)",
		"Full runtime loaded plugin list (config-only inference for password policy and keyring)",
	}
}

func finalizeMysqlPostureArrays(out *payload.MysqlPosture) {
	if out == nil {
		return
	}
	if out.CollectorWarnings == nil {
		out.CollectorWarnings = []string{}
	}
	if out.LimitedWithoutSQLAccess == nil {
		out.LimitedWithoutSQLAccess = []string{}
	}
}

func applyMysqlOptsToPosture(opts map[string]string, filesRead int, primaryPath string, pwdExposed bool, ctx context.Context, warnings *[]string, out *payload.MysqlPosture) {
	setStr := func(dst **string, key string, max int) {
		v := strings.TrimSpace(opts[key])
		if v == "" {
			return
		}
		*dst = shared.StringPtr(shared.TruncateRunes(v, max))
	}
	setStr(&out.BindAddress, "bind_address", 128)
	setStr(&out.SocketPath, "socket", 512)
	setStr(&out.DefaultAuthPlugin, "default_authentication_plugin", 128)
	setStr(&out.SecureAuth, "secure_auth", 32)
	setStr(&out.SslCa, "ssl_ca", 512)
	setStr(&out.SslCert, "ssl_cert", 512)
	setStr(&out.SslKey, "ssl_key", 512)
	setStr(&out.RequireSecureTransport, "require_secure_transport", 32)
	setStr(&out.TlsVersion, "tls_version", 128)
	setStr(&out.LocalInfile, "local_infile", 32)
	setStr(&out.SecureFilePriv, "secure_file_priv", 512)
	setStr(&out.SymbolicLinks, "symbolic_links", 32)
	setStr(&out.LogRaw, "log_raw", 32)
	setStr(&out.GeneralLog, "general_log", 32)
	setStr(&out.RunUser, "user", 64)
	setStr(&out.Datadir, "datadir", 512)
	setStr(&out.InnodbEncryptTables, "innodb_encrypt_tables", 64)
	setStr(&out.DefaultTableEncryption, "default_table_encryption", 64)
	if p := parseMysqlPortInt(opts["port"]); p != nil {
		out.Port = p
	} else if filesRead > 0 {
		out.Port = shared.IntPtr(3306)
	}
	if _, ok := opts["skip_networking"]; ok {
		out.SkipNetworking = mysqlCnfBoolishPtr(opts["skip_networking"])
	}
	if _, ok := opts["skip_grant_tables"]; ok {
		out.SkipGrantTables = mysqlCnfBoolishPtr(opts["skip_grant_tables"])
	}
	out.TlsConfigured = mysqlTlsConfiguredPtr(opts, filesRead)
	out.PasswordPolicyPlugin = mysqlInferPasswordPolicyPlugin(opts)
	out.KeyringPlugin = mysqlInferKeyringPlugin(opts)
	if ap := strings.ToLower(strings.TrimSpace(opts["default_authentication_plugin"])); ap != "" {
		v := strings.Contains(ap, "auth_socket") || strings.Contains(ap, "unix_socket")
		out.AuthSocketOrUnix = shared.BoolPtr(v)
	}
	out.MyCnfPasswordsExposed = shared.BoolPtr(pwdExposed)
	if primaryPath != "" {
		out.ConfigFilePermissions = filePermissionSummary(primaryPath)
	}
	dd := strings.TrimSpace(opts["datadir"])
	if dd != "" && filepath.IsAbs(dd) {
		out.DatadirPermissions = filePermissionSummary(dd)
	}
	le := resolveMysqlErrorLogPath(dd, opts["log_error"])
	if le != "" {
		out.ErrorLogPermissions = filePermissionSummary(le)
	}
	if uid, ok := discoverMysqldProcUID(); ok {
		un := procUsernameForUID(uid)
		cfgU := strings.TrimSpace(opts["user"])
		if cfgU != "" && un != "" && !strings.EqualFold(cfgU, un) {
			*warnings = append(*warnings, fmt.Sprintf("config user=%q differs from running mysqld process user %q", cfgU, un))
		}
		if out.RunUser == nil && un != "" {
			out.RunUser = shared.StringPtr(shared.TruncateRunes(un, 64))
		}
	}
	if strings.EqualFold(strings.TrimSpace(opts["user"]), "root") {
		*warnings = append(*warnings, "mysqld config user=root (running as superuser is a security risk).")
	}
	out.IsContainerized = shared.HostIsContainerized()
	port := 3306
	if out.Port != nil {
		port = *out.Port
	}
	skipNet := out.SkipNetworking != nil && *out.SkipNetworking
	lines := collectMysqlSsMysqldLines(ctx)
	out.RuntimeListenCheck = buildMysqlRuntimeListenCheck(out.BindAddress, port, skipNet, lines, warnings)
}

func mysqlTlsConfiguredPtr(opts map[string]string, filesRead int) *bool {
	if filesRead == 0 {
		return nil
	}
	ca := strings.TrimSpace(opts["ssl_ca"])
	cert := strings.TrimSpace(opts["ssl_cert"])
	key := strings.TrimSpace(opts["ssl_key"])
	if ca != "" && cert != "" && key != "" {
		return shared.BoolPtr(true)
	}
	if ca == "" && cert == "" && key == "" {
		return shared.BoolPtr(false)
	}
	return shared.BoolPtr(false)
}

func resolveMysqlErrorLogPath(datadir, logError string) string {
	le := strings.TrimSpace(logError)
	if le == "" {
		return ""
	}
	low := strings.ToLower(le)
	if low == "stderr" || strings.HasPrefix(low, "syslog") {
		return ""
	}
	if filepath.IsAbs(le) {
		return filepath.Clean(le)
	}
	if datadir == "" {
		return ""
	}
	return filepath.Clean(filepath.Join(datadir, le))
}

const mysqlSsTimeout = 6 * time.Second

func collectMysqlSsMysqldLines(ctx context.Context) []string {
	subCtx, cancel := context.WithTimeout(ctx, mysqlSsTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, "ss", "-tlnp")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	var rows []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}
		if !strings.Contains(line, "mysqld") && !strings.Contains(line, "mariadb") {
			continue
		}
		rows = append(rows, shared.TruncateRunes(line, 280))
	}
	return rows
}

func buildMysqlRuntimeListenCheck(bind *string, port int, skipNet bool, ssLines []string, warnings *[]string) *string {
	if len(ssLines) == 0 {
		if skipNet {
			return shared.StringPtr("ss -tlnp: no mysqld/mariadb TCP lines (consistent with skip_networking if no listeners expected)")
		}
		return shared.StringPtr(fmt.Sprintf("ss -tlnp: no mysqld/mariadb listener line for port %d (process may be down or using socket only)", port))
	}
	joined := strings.Join(ssLines, " | ")
	if skipNet {
		*warnings = append(*warnings, "skip_networking set in config but ss shows mysqld TCP listeners — verify effective configuration.")
	}
	if bind != nil {
		b := strings.TrimSpace(*bind)
		if b != "" && mysqlBindImpliesAllInterfaces(b) {
			return shared.StringPtr("bind_address allows all interfaces; ss: " + joined)
		}
		if b != "" && (b == "127.0.0.1" || b == "::1") {
			return shared.StringPtr("bind_address is loopback; ss: " + joined)
		}
	}
	return shared.StringPtr("ss -tlnp (mysqld/mariadb): " + joined)
}

func mysqlServiceStatePtr(ctx context.Context, services []payload.ServiceEntry) (*string, []string) {
	s := mysqlServiceState(ctx, services)
	if s == "running" || s == "stopped" {
		return shared.StringPtr(s), nil
	}
	return nil, []string{"mysql/mariadb service_state could not be determined as running or stopped from systemd inventory or systemctl is-active."}
}

func resolveMysqlServerBinary() (path string, engine string) {
	candidates := []struct {
		name   string
		engine string
	}{
		{"mysqld", "mysql"},
		{"mariadbd", "mariadb"},
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c.name); err == nil {
			return p, c.engine
		}
	}
	extra := []struct {
		path   string
		engine string
	}{
		{"/usr/sbin/mysqld", "mysql"},
		{"/usr/sbin/mariadbd", "mariadb"},
		{"/usr/libexec/mysqld", "mysql"},
	}
	for _, e := range extra {
		if shared.FileExistsRegular(e.path) {
			return e.path, e.engine
		}
	}
	return "", "unknown"
}

func engineFromVersionString(v string) string {
	low := strings.ToLower(v)
	if strings.Contains(low, "mariadb") {
		return "mariadb"
	}
	if strings.Contains(low, "mysql") {
		return "mysql"
	}
	return "unknown"
}

func trimMysqlPostureErr(prefix string, err error, combined []byte) string {
	msg := strings.TrimSpace(string(combined))
	if msg == "" {
		return prefix + err.Error()
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return prefix + msg
}

func mysqlServiceState(ctx context.Context, services []payload.ServiceEntry) string {
	want := map[string]struct{}{
		"mysqld.service":         {},
		"mariadb.service":        {},
		"mysql.service":          {},
		"mariadb-server.service": {},
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
	for _, unit := range []string{"mysqld.service", "mariadb.service", "mysql.service", "mariadb-server.service"} {
		if st := systemdutil.SystemctlIsActiveState(ctx, unit); st == "running" || st == "stopped" {
			return st
		}
	}
	return ""
}
