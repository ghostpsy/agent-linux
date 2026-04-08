//go:build linux

package identity

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const sshdPath = "sshd"

// CollectHostSSH reads effective sshd settings from `sshd -T`.
func CollectHostSSH() (*payload.HostSSH, string) {
	output, err := runSSHDT()
	if err != nil {
		return nil, shared.CollectionNote("OpenSSH effective configuration could not be read from sshd.")
	}
	cfg := parseSSHDTOutput(output)
	return buildHostSSH(cfg), ""
}

type sshdConfig struct {
	permitRootLogin     string
	passwordAuth        string
	challengeAuth       string
	listenAddresses     []string
	kexAlgorithms       []string
	ciphers             []string
	maxAuthTries        *int
	clientAliveInterval *int
	clientAliveCountMax *int
	allowUsersRaw       string
	denyUsersRaw        string
	subsystem           string
	usePAM              string
	x11Forwarding       string
}

func runSSHDT() ([]byte, error) {
	command := exec.Command(sshdPath, "-T")
	command.Env = shared.EnvLocaleC()
	return command.CombinedOutput()
}

func parseSSHDTOutput(output []byte) sshdConfig {
	cfg := sshdConfig{}
	lines := strings.Split(string(output), "\n")
	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")
		switch key {
		case "permitrootlogin":
			cfg.permitRootLogin = value
		case "passwordauthentication":
			cfg.passwordAuth = value
		case "challengeresponseauthentication", "kbdinteractiveauthentication":
			cfg.challengeAuth = value
		case "listenaddress":
			cfg.listenAddresses = append(cfg.listenAddresses, value)
		case "kexalgorithms":
			cfg.kexAlgorithms = splitCommaList(value)
		case "ciphers":
			cfg.ciphers = splitCommaList(value)
		case "maxauthtries":
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n >= 0 {
				cfg.maxAuthTries = intPtr(n)
			}
		case "clientaliveinterval":
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n >= 0 {
				cfg.clientAliveInterval = intPtr(n)
			}
		case "clientalivecountmax":
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n >= 0 {
				cfg.clientAliveCountMax = intPtr(n)
			}
		case "allowusers":
			cfg.allowUsersRaw = value
		case "denyusers":
			cfg.denyUsersRaw = value
		case "subsystem":
			if cfg.subsystem == "" {
				cfg.subsystem = value
			}
		case "usepam":
			cfg.usePAM = value
		case "x11forwarding":
			cfg.x11Forwarding = value
		}
	}
	return cfg
}

func splitCommaList(v string) []string {
	rawParts := strings.Split(v, ",")
	items := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		items = append(items, item)
	}
	return items
}

func buildHostSSH(cfg sshdConfig) *payload.HostSSH {
	allowPresent := strings.TrimSpace(cfg.allowUsersRaw) != ""
	denyPresent := strings.TrimSpace(cfg.denyUsersRaw) != ""
	out := &payload.HostSSH{
		PermitRootLogin:            normalizeOnOffValue(cfg.permitRootLogin),
		PasswordAuthentication:     normalizeOnOffValue(cfg.passwordAuth),
		ChallengeResponseAuth:      normalizeOnOffValue(cfg.challengeAuth),
		ListenAddresses:            normalizeListenAddresses(cfg.listenAddresses),
		KexAlgorithmsSample:        truncateList(cfg.kexAlgorithms, 16, 128),
		CiphersSample:              truncateList(cfg.ciphers, 16, 128),
		MaxAuthTries:               cfg.maxAuthTries,
		ClientAliveIntervalSeconds: cfg.clientAliveInterval,
		ClientAliveCountMax:        cfg.clientAliveCountMax,
		AllowUsersPresent:          allowPresent,
		DenyUsersPresent:           denyPresent,
		Subsystem:                  shared.TruncateRunes(strings.TrimSpace(cfg.subsystem), 256),
		UsePAM:                     normalizeOnOffValue(cfg.usePAM),
		X11Forwarding:              normalizeOnOffValue(cfg.x11Forwarding),
	}
	return out
}

func intPtr(n int) *int {
	return &n
}

func normalizeOnOffValue(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	switch normalized {
	case "yes", "no", "without-password", "prohibit-password", "forced-commands-only":
		return normalized
	default:
		return ""
	}
}

func normalizeListenAddresses(addresses []string) []string {
	if len(addresses) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		value := strings.TrimSpace(strings.Trim(address, "\""))
		if value == "" {
			continue
		}
		if host, port, found := strings.Cut(value, ":"); found {
			if _, portErr := strconv.Atoi(port); portErr == nil && host != "" {
				value = host + ":" + port
			}
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, shared.TruncateRunes(value, 128))
	}
	return normalized
}

func truncateList(values []string, maxItems, maxItemRunes int) []string {
	if len(values) == 0 {
		return nil
	}
	if len(values) > maxItems {
		values = values[:maxItems]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		out = append(out, shared.TruncateRunes(value, maxItemRunes))
	}
	return out
}
