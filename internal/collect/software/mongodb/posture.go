//go:build linux

// Package mongodb collects bounded security posture for MongoDB servers.
// No database contents, user lists, or credentials.
package mongodb

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const configReadLimit int64 = 64 << 10

var (
	reVersion = regexp.MustCompile(`([\d]+\.[\d]+\.[\d]+)`)
)

var (
	binNames     = []string{"mongod"}
	commonPaths  = []string{"/usr/bin/mongod", "/usr/local/bin/mongod"}
	serviceNames = []string{"mongod.service", "mongodb.service"}
	configPaths  = []string{"/etc/mongod.conf", "/etc/mongodb.conf"}
)

// CollectMongodbPosture detects and collects MongoDB server posture.
// Returns nil when no mongod binary is found.
func CollectMongodbPosture(ctx context.Context, services []payload.ServiceEntry) *payload.MongodbPosture {
	bin := resolveBinary()
	if bin == "" {
		return nil
	}

	out := &payload.MongodbPosture{
		Detected: true,
		BinPath:  bin,
	}
	out.Version = extractVersion(ctx, bin)
	out.ServiceState = serviceState(ctx, services)
	parseConfig(out)
	if out.CollectorWarnings == nil {
		out.CollectorWarnings = []string{}
	}
	return out
}

func resolveBinary() string {
	for _, name := range binNames {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range commonPaths {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func extractVersion(ctx context.Context, bin string) *string {
	cmd := exec.CommandContext(ctx, bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	m := reVersion.FindStringSubmatch(string(out))
	if len(m) >= 2 {
		return shared.StringPtr(m[1])
	}
	return nil
}

func serviceState(ctx context.Context, services []payload.ServiceEntry) *string {
	want := make(map[string]struct{}, len(serviceNames))
	for _, n := range serviceNames {
		want[n] = struct{}{}
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := systemdutil.MapActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	for _, n := range serviceNames {
		if st := systemdutil.SystemctlIsActiveState(ctx, n); st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	return nil
}

func parseConfig(out *payload.MongodbPosture) {
	for _, p := range configPaths {
		b, err := shared.ReadFileBounded(p, configReadLimit)
		if err != nil {
			continue
		}
		parseYamlConfig(string(b), out)
		return
	}
}

func parseYamlConfig(content string, out *payload.MongodbPosture) {
	var inTlsSection, inSecuritySection, inStorageSection, inJournalSection bool

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Track top-level YAML sections (indent 0)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			section := strings.TrimSuffix(trimmed, ":")
			inTlsSection = false
			inSecuritySection = false
			inStorageSection = false
			inJournalSection = false
			switch section {
			case "net":
				// net section contains tls sub-section, bindIp, port
			case "security":
				inSecuritySection = true
			case "storage":
				inStorageSection = true
			}
			continue
		}

		// Track sub-sections
		if indent > 0 && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			sub := strings.TrimSuffix(trimmed, ":")
			if sub == "tls" || sub == "ssl" {
				inTlsSection = true
				inSecuritySection = false
				inJournalSection = false
				continue
			}
			if sub == "journal" && inStorageSection {
				inJournalSection = true
				inSecuritySection = false
				inTlsSection = false
				continue
			}
		}

		key, val := splitYamlLine(trimmed)
		if key == "" {
			continue
		}

		switch {
		case key == "bindIp" || key == "bindip":
			out.BindIp = shared.StringPtr(val)
		case key == "port" && !inTlsSection:
			if port, err := strconv.Atoi(val); err == nil {
				out.Port = shared.IntPtr(port)
			}
		case key == "mode" && inTlsSection:
			out.TlsMode = shared.StringPtr(val)
		case key == "authorization" && inSecuritySection:
			out.AuthEnabled = shared.BoolPtr(strings.EqualFold(val, "enabled"))
		case key == "keyFile" || key == "keyfile":
			out.KeyFilePresent = shared.BoolPtr(val != "")
		case key == "enabled" && inJournalSection:
			out.JournalEnabled = boolFromYaml(val)
		}
	}
}

func splitYamlLine(line string) (string, string) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", ""
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	return key, val
}

func boolFromYaml(val string) *bool {
	switch strings.ToLower(val) {
	case "true":
		return shared.BoolPtr(true)
	case "false":
		return shared.BoolPtr(false)
	}
	return nil
}
