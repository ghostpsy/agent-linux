//go:build linux

package software

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	postgresPostureCmdTimeout = 10 * time.Second
	maxPgHbaLinesScanned      = 512
)

var (
	rePostgresListenLine = regexp.MustCompile(`(?i)^\s*listen_addresses\s*=\s*([^#]+)`)
	rePostgresPortLine   = regexp.MustCompile(`(?i)^\s*port\s*=\s*(\d+)`)
	rePostgresSslLine    = regexp.MustCompile(`(?i)^\s*ssl\s*=\s*(\S+)`)
)

// CollectPostgresPosture collects bounded PostgreSQL server hints when the postgres binary is present.
// No SQL connections; pg_hba is aggregated into counts only (no database/user/address literals).
func CollectPostgresPosture(ctx context.Context, services []payload.ServiceEntry) *payload.PostgresPosture {
	bin := resolvePostgresServerBinary()
	if bin == "" {
		return nil
	}
	out := &payload.PostgresPosture{
		Detected:     true,
		BinPath:      bin,
		ServiceState: postgresServiceState(ctx, services),
	}
	subCtx, cancel := context.WithTimeout(ctx, postgresPostureCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, bin, "-V")
	combined, err := cmd.CombinedOutput()
	if err != nil {
		out.Error = trimPostgresPostureErr("version: ", err, combined)
	} else {
		line := strings.TrimSpace(string(combined))
		if i := strings.Index(line, "\n"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out.Version = shared.TruncateRunes(line, 512)
	}
	if lh := collectPostgresListenHints(ctx); lh != nil {
		out.ListenHints = lh
	}
	if hh := collectPostgresHbaHints(ctx); hh != nil {
		out.HbaHints = hh
	}
	return out
}

func resolvePostgresServerBinary() string {
	if p, err := exec.LookPath("postgres"); err == nil {
		return p
	}
	matches, _ := filepath.Glob("/usr/lib/postgresql/*/bin/postgres")
	sort.Strings(matches)
	for _, p := range matches {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	for _, p := range []string{"/usr/bin/postgres", "/usr/local/pgsql/bin/postgres"} {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func trimPostgresPostureErr(prefix string, err error, combined []byte) string {
	msg := strings.TrimSpace(string(combined))
	if msg == "" {
		return prefix + err.Error()
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return prefix + msg
}

func discoverPostgresqlConfPath() string {
	globs := []string{
		"/etc/postgresql/*/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/postgres/data/postgresql.conf",
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		sort.Strings(matches)
		for _, p := range matches {
			if shared.FileExistsRegular(p) {
				return p
			}
		}
	}
	return ""
}

func hbaPathBesideConf(confPath string) string {
	if confPath == "" {
		return ""
	}
	hba := filepath.Join(filepath.Dir(confPath), "pg_hba.conf")
	if shared.FileExistsRegular(hba) {
		return hba
	}
	return ""
}

func discoverPgHbaPathStandalone() string {
	globs := []string{
		"/etc/postgresql/*/main/pg_hba.conf",
		"/var/lib/pgsql/data/pg_hba.conf",
		"/var/lib/postgres/data/pg_hba.conf",
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		sort.Strings(matches)
		for _, p := range matches {
			if shared.FileExistsRegular(p) {
				return p
			}
		}
	}
	return ""
}

func collectPostgresListenHints(ctx context.Context) *payload.PostgresListenHints {
	if ctx.Err() != nil {
		return nil
	}
	p := discoverPostgresqlConfPath()
	if p == "" {
		return nil
	}
	b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return nil
	}
	var listen, ssl, portStr string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if m := rePostgresListenLine.FindStringSubmatch(line); len(m) > 1 {
			listen = strings.TrimSpace(strings.Trim(m[1], `"'`))
			if i := strings.Index(listen, "#"); i >= 0 {
				listen = strings.TrimSpace(listen[:i])
			}
		}
		if m := rePostgresPortLine.FindStringSubmatch(line); len(m) > 1 {
			portStr = m[1]
		}
		if m := rePostgresSslLine.FindStringSubmatch(line); len(m) > 1 {
			ssl = strings.TrimSpace(strings.Trim(m[1], `"'`))
		}
	}
	if listen == "" && portStr == "" && ssl == "" {
		return nil
	}
	h := &payload.PostgresListenHints{ConfigPathUsed: p}
	if listen != "" {
		h.ListenAddresses = shared.TruncateRunes(listen, 256)
		t := listenAddressesImpliesAll(listen)
		h.ListenImpliesAllAddresses = &t
	}
	if portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port >= 1 && port <= 65535 {
			h.Port = &port
		}
	}
	if ssl != "" {
		h.Ssl = shared.TruncateRunes(ssl, 64)
	}
	return h
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

func collectPostgresHbaHints(ctx context.Context) *payload.PostgresHbaHints {
	if ctx.Err() != nil {
		return nil
	}
	hbaPath := hbaPathBesideConf(discoverPostgresqlConfPath())
	if hbaPath == "" {
		hbaPath = discoverPgHbaPathStandalone()
	}
	if hbaPath == "" {
		return nil
	}
	b, err := shared.ReadFileBounded(hbaPath, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return nil
	}
	return analyzePgHba(string(b), hbaPath)
}

func stripPgHbaLineComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func analyzePgHba(content, hbaPath string) *payload.PostgresHbaHints {
	var linesScanned, host, hostssl, hostnossl, localN int
	var trustN, rejectN, passwordFamilyN, peerIdentN int
	for _, raw := range strings.Split(content, "\n") {
		if linesScanned >= maxPgHbaLinesScanned {
			break
		}
		line := stripPgHbaLineComment(raw)
		if line == "" {
			continue
		}
		linesScanned++
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		typ := strings.ToLower(parts[0])
		method := pgHbaAuthMethod(parts, typ)
		switch typ {
		case "local":
			localN++
		case "host":
			host++
		case "hostssl":
			hostssl++
		case "hostnossl":
			hostnossl++
		default:
			continue
		}
		switch method {
		case "trust":
			trustN++
		case "reject":
			rejectN++
		case "md5", "password", "scram-sha-256":
			passwordFamilyN++
		case "peer", "ident":
			peerIdentN++
		}
	}
	if linesScanned == 0 && host == 0 && hostssl == 0 && hostnossl == 0 && localN == 0 {
		return nil
	}
	return &payload.PostgresHbaHints{
		FilePathUsed:              shared.TruncateRunes(hbaPath, 512),
		LinesScanned:              linesScanned,
		HostRuleCount:             host,
		HostsslRuleCount:          hostssl,
		HostnosslRuleCount:        hostnossl,
		LocalRuleCount:            localN,
		TrustMethodCount:          trustN,
		RejectMethodCount:         rejectN,
		PasswordFamilyMethodCount: passwordFamilyN,
		PeerOrIdentMethodCount:    peerIdentN,
	}
}

func pgHbaAuthMethod(parts []string, typ string) string {
	var minIdx int
	switch typ {
	case "local":
		minIdx = 3
	case "host", "hostssl", "hostnossl":
		minIdx = 4
	default:
		return ""
	}
	if len(parts) <= minIdx {
		return ""
	}
	methodIdx := len(parts) - 1
	method := strings.ToLower(strings.Trim(parts[methodIdx], `"'`))
	if strings.Contains(method, "=") && methodIdx > minIdx {
		methodIdx--
		method = strings.ToLower(strings.Trim(parts[methodIdx], `"'`))
	}
	return method
}

func postgresServiceState(ctx context.Context, services []payload.ServiceEntry) string {
	for _, e := range services {
		if e.Name == "postgresql.service" {
			st := systemdutil.MapActiveStateForPosture(e.ActiveState)
			if st == "running" || st == "stopped" {
				return st
			}
		}
		if strings.HasPrefix(e.Name, "postgresql@") && strings.HasSuffix(e.Name, ".service") {
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
