//go:build linux

package identity

import (
	"bufio"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	pwqualityConfPath   = "/etc/security/pwquality.conf"
	maxPwqualityKeys    = 64
	maxPamPasswordLines = 32
)

var pamPasswordCandidates = []string{
	"/etc/pam.d/common-password",
	"/etc/pam.d/password-auth",
	"/etc/pam.d/system-auth",
}

// CollectPasswordPolicyFingerprint reads pwquality.conf and PAM password stack lines (no secrets).
func CollectPasswordPolicyFingerprint() *payload.PasswordPolicyFingerprint {
	out := &payload.PasswordPolicyFingerprint{}
	out.PwqualityKeys = readPwqualityConf()
	out.PamPasswordRequisiteLines = readPamPasswordStackLines()
	if len(out.PwqualityKeys) == 0 && len(out.PamPasswordRequisiteLines) == 0 {
		out.Error = "password policy fingerprint unavailable"
	}
	return out
}

func readPwqualityConf() []payload.PwqualityKV {
	f, err := os.Open(pwqualityConfPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var out []payload.PwqualityKV
	for sc.Scan() && len(out) < maxPwqualityKeys {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k := strings.TrimSpace(key)
		v := strings.TrimSpace(val)
		if k == "" {
			continue
		}
		out = append(out, payload.PwqualityKV{
			Key:   shared.TruncateRunes(k, 64),
			Value: shared.TruncateRunes(v, 128),
		})
	}
	return out
}

func readPamPasswordStackLines() []string {
	var lines []string
	for _, path := range pamPasswordCandidates {
		lines = append(lines, readPamFilePasswordLines(path)...)
		if len(lines) >= maxPamPasswordLines {
			break
		}
	}
	if len(lines) > maxPamPasswordLines {
		lines = lines[:maxPamPasswordLines]
	}
	return lines
}

func readPamFilePasswordLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "password") && (strings.Contains(lower, "pam_") || strings.Contains(lower, "include")) {
			out = append(out, shared.TruncateRunes(line, 256))
		}
		if len(out) >= maxPamPasswordLines {
			break
		}
	}
	return out
}
