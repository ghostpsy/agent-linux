//go:build linux

package postfix

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const postconfTimeout = 12 * time.Second

// MtaPostconfKeys is the minimal allowlist for mta_fingerprint (single postconf invocation).
var MtaPostconfKeys = []string{
	"inet_interfaces",
	"mynetworks_style",
	"smtpd_recipient_restrictions",
}

var postconfKeysPosture = []string{
	"config_directory",
	"mail_version",
	"inet_interfaces",
	"inet_protocols",
	"mynetworks",
	"smtpd_relay_restrictions",
	"relay_domains",
	"smtpd_recipient_restrictions",
	"smtpd_tls_security_level",
	"smtp_tls_security_level",
	"smtpd_tls_protocols",
	"smtpd_tls_mandatory_ciphers",
	"tls_preempt_cipherlist",
	"smtpd_sasl_auth_enable",
	"smtpd_sasl_security_options",
	"smtpd_tls_auth_only",
	"smtpd_sender_restrictions",
	"smtpd_helo_required",
	"smtpd_helo_restrictions",
	"smtpd_sender_login_maps",
	"smtpd_banner",
	"smtpd_client_connection_rate_limit",
	"smtpd_client_message_rate_limit",
	"smtpd_error_sleep_time",
	"smtpd_hard_error_limit",
	"message_size_limit",
	"mail_owner",
}

// QueryPostconf runs postconf with an allowlisted parameter list only (no postconf -n dump).
func QueryPostconf(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	subCtx, cancel := context.WithTimeout(ctx, postconfTimeout)
	defer cancel()
	args := append([]string{"postconf"}, keys...)
	cmd := exec.CommandContext(subCtx, args[0], args[1:]...)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail != "" {
			return nil, fmt.Errorf("%w: %s", err, detail)
		}
		return nil, err
	}
	return parsePostconfOutput(string(raw)), nil
}

func parsePostconfOutput(raw string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" {
			m[k] = v
		}
	}
	return m
}

func truncatePostconfValue(k, v string) string {
	switch k {
	case "mynetworks", "smtpd_recipient_restrictions", "smtpd_relay_restrictions",
		"smtpd_helo_restrictions", "smtpd_sender_restrictions", "relay_domains",
		"smtpd_banner":
		return shared.TruncateRunes(v, 512)
	case "smtpd_tls_mandatory_ciphers", "smtpd_tls_protocols":
		return shared.TruncateRunes(v, 256)
	case "mail_version", "inet_interfaces", "inet_protocols", "smtpd_tls_security_level",
		"smtp_tls_security_level", "smtpd_sasl_security_options", "config_directory", "mail_owner":
		return shared.TruncateRunes(v, 256)
	case "smtpd_client_connection_rate_limit", "smtpd_client_message_rate_limit",
		"smtpd_error_sleep_time", "smtpd_hard_error_limit", "message_size_limit":
		return shared.TruncateRunes(v, 64)
	default:
		return shared.TruncateRunes(v, 256)
	}
}
