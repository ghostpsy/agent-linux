//go:build linux

package software

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	apacheHardeningSSLProtocolMaxRunes    = 256
	apacheHardeningSSLCipherMaxRunes      = 128
	apacheHardeningOptionsLineMaxRunes    = 128
	apacheHardeningOptionsMaxLines        = 4
	apacheHardeningSecurityModuleMaxItems = 32
	apacheHardeningModuleNameMaxRunes     = 64
	apacheHardeningModsEnabledGlobMax     = 48
	apacheHardeningConfModulesGlobMax     = 32
	apacheHardeningModuleFileReadLimit    = 4096
)

var (
	reApacheTraceEnable   = regexp.MustCompile(`(?i)TraceEnable\s+(\S+)`)
	reApacheSSLProtocol   = regexp.MustCompile(`(?i)SSLProtocol\s+([^\n#]+)`)
	reApacheSSLCipher     = regexp.MustCompile(`(?i)SSLCipherSuite\s+([^\n#]+)`)
	reApacheAllowOverride = regexp.MustCompile(`(?i)AllowOverride\s+(\S+)`)
	reApacheLoadModule    = regexp.MustCompile(`(?i)^\s*LoadModule\s+(\S+)\s+`)
)

// collectApacheHardeningHints reads bounded distro main config and optional module stub paths (no Include walk).
func collectApacheHardeningHints(ctx context.Context) *payload.ApacheHardeningHints {
	_ = ctx
	h := &payload.ApacheHardeningHints{}
	apPaths := []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/conf/httpd.conf"}
	var mainBody []byte
	for _, p := range apPaths {
		b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
		if err != nil {
			continue
		}
		mainBody = b
		break
	}
	if len(mainBody) > 0 {
		applyApacheMainConfigHardening(string(mainBody), h)
	}
	apacheAppendSecurityRelevantModules(h)
	if apacheHardeningHintsEmpty(h) {
		return nil
	}
	return h
}

func applyApacheMainConfigHardening(content string, h *payload.ApacheHardeningHints) {
	if m := reApacheTraceEnable.FindStringSubmatch(content); len(m) > 1 {
		h.TraceEnable = truncateRunes(strings.TrimSpace(m[1]), 16)
	}
	if m := reApacheSSLProtocol.FindStringSubmatch(content); len(m) > 1 {
		h.SSLProtocolSummary = truncateRunes(strings.TrimSpace(m[1]), apacheHardeningSSLProtocolMaxRunes)
	}
	if m := reApacheSSLCipher.FindStringSubmatch(content); len(m) > 1 {
		h.SSLCipherSuiteSummary = truncateRunes(strings.TrimSpace(m[1]), apacheHardeningSSLCipherMaxRunes)
	}
	if m := reApacheAllowOverride.FindStringSubmatch(content); len(m) > 1 {
		h.AllowOverrideMain = truncateRunes(strings.TrimSpace(m[1]), 64)
	}
	samples, idxHint := apacheAnalyzeOptionsLines(content)
	if len(samples) > 0 {
		h.OptionsLinesSample = samples
	}
	if idxHint != nil {
		h.IndexesInOptionsHint = idxHint
	}
}

func apacheAnalyzeOptionsLines(content string) (samples []string, indexesHint *bool) {
	var optionLines []string
	for _, line := range strings.Split(content, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		lower := strings.ToLower(trim)
		if !strings.HasPrefix(lower, "options ") && !strings.HasPrefix(lower, "options\t") {
			continue
		}
		optionLines = append(optionLines, trim)
	}
	if len(optionLines) == 0 {
		return nil, nil
	}
	for i := 0; i < len(optionLines) && len(samples) < apacheHardeningOptionsMaxLines; i++ {
		samples = append(samples, truncateRunes(optionLines[i], apacheHardeningOptionsLineMaxRunes))
	}
	anyEnable := false
	for _, ol := range optionLines {
		if optionsLineEnablesIndexes(ol) {
			anyEnable = true
			break
		}
	}
	v := anyEnable
	return samples, &v
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

// apacheAppendSecurityRelevantModules collects LoadModule names from bounded stub files that match a
// curated security-relevant set (exhaustive within scanned files for that set, not an arbitrary sample).
func apacheAppendSecurityRelevantModules(h *payload.ApacheHardeningHints) {
	seen := map[string]struct{}{}
	var names []string
	for _, g := range []struct {
		pattern string
		max     int
	}{
		{"/etc/apache2/mods-enabled/*.load", apacheHardeningModsEnabledGlobMax},
		{"/etc/httpd/conf.modules.d/*.conf", apacheHardeningConfModulesGlobMax},
	} {
		matches, err := filepath.Glob(g.pattern)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		if len(matches) > g.max {
			matches = matches[:g.max]
		}
		for _, p := range matches {
			b, err := shared.ReadFileBounded(p, int64(apacheHardeningModuleFileReadLimit))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if m := reApacheLoadModule.FindStringSubmatch(line); len(m) > 1 {
					name := truncateRunes(strings.TrimSpace(m[1]), apacheHardeningModuleNameMaxRunes)
					if name == "" || !isSecurityRelevantApacheModule(name) {
						continue
					}
					if _, ok := seen[name]; ok {
						continue
					}
					seen[name] = struct{}{}
					names = append(names, name)
				}
			}
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	if len(names) > apacheHardeningSecurityModuleMaxItems {
		names = names[:apacheHardeningSecurityModuleMaxItems]
	}
	h.SecurityRelevantModules = names
}

func apacheHardeningHintsEmpty(h *payload.ApacheHardeningHints) bool {
	if h == nil {
		return true
	}
	if h.TraceEnable != "" || h.SSLProtocolSummary != "" || h.SSLCipherSuiteSummary != "" || h.AllowOverrideMain != "" {
		return false
	}
	if len(h.OptionsLinesSample) > 0 || h.IndexesInOptionsHint != nil {
		return false
	}
	return len(h.SecurityRelevantModules) == 0
}

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
