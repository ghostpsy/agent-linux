//go:build linux

package security

import (
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const fail2banJailNameMaxRunes = 64

type fail2banNamedConfig struct {
	Path string
	Body []byte
}

// fail2banParseResult is the merged view of fail2ban jail.* ini-style files.
type fail2banParseResult struct {
	EnabledJails         []string
	JailSectionCountHint int
	DefaultBantime       string
	DefaultFindtime      string
	DefaultMaxRetry      string
}

// mergeFail2banIniBodies applies later files over earlier ones (fail2ban jail.d overlay semantics).
func mergeFail2banIniBodies(files []fail2banNamedConfig) fail2banParseResult {
	state := make(map[string]map[string]string)
	for _, f := range files {
		sectionKVs := parseFail2banIniFile(f.Body)
		for sec, kvs := range sectionKVs {
			if state[sec] == nil {
				state[sec] = make(map[string]string)
			}
			for k, v := range kvs {
				state[sec][k] = v
			}
		}
	}
	out := fail2banParseResult{}
	if def, ok := state["DEFAULT"]; ok {
		out.DefaultBantime = strings.TrimSpace(def["bantime"])
		out.DefaultFindtime = strings.TrimSpace(def["findtime"])
		out.DefaultMaxRetry = strings.TrimSpace(def["maxretry"])
	}
	jailNames := make([]string, 0, len(state))
	for name := range state {
		n := strings.TrimSpace(name)
		if n == "" || strings.EqualFold(n, "default") {
			continue
		}
		jailNames = append(jailNames, n)
	}
	sort.Strings(jailNames)
	out.JailSectionCountHint = len(jailNames)
	var enabled []string
	for _, name := range jailNames {
		kvs := state[name]
		if jailSectionEnabled(kvs) {
			enabled = append(enabled, shared.TruncateRunes(name, fail2banJailNameMaxRunes))
		}
	}
	sort.Strings(enabled)
	if len(enabled) > fail2banMaxEnabledJails {
		enabled = enabled[:fail2banMaxEnabledJails]
	}
	out.EnabledJails = enabled
	return out
}

const fail2banMaxEnabledJails = 48

func jailSectionEnabled(kvs map[string]string) bool {
	if kvs == nil {
		return false
	}
	v, ok := kvs["enabled"]
	if !ok {
		return false
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "true" || v == "1" || v == "yes"
}

// parseFail2banIniFile returns section -> lowercased key -> trimmed value for one file body.
func parseFail2banIniFile(body []byte) map[string]map[string]string {
	out := make(map[string]map[string]string)
	section := ""
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if len(line) >= 2 && line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if out[section] == nil {
				out[section] = make(map[string]string)
			}
			continue
		}
		if section == "" {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(strings.ToLower(line[:idx]))
		v := strings.TrimSpace(line[idx+1:])
		if i := strings.IndexAny(v, "#;"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if k == "" {
			continue
		}
		if out[section] == nil {
			out[section] = make(map[string]string)
		}
		out[section][k] = v
	}
	return out
}
