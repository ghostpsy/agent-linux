//go:build linux

package postfix

import (
	"context"
	"os/exec"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

// CollectPostfixPosture collects bounded Postfix security posture via allowlisted postconf keys and bounded master.cf parse.
// Returns nil when no postfix binary is found on PATH or common paths.
func CollectPostfixPosture(ctx context.Context, services []payload.ServiceEntry) *payload.PostfixPosture {
	bin := resolvePostfixBinary()
	if bin == "" {
		return nil
	}
	out := &payload.PostfixPosture{Detected: true, BinPath: bin}
	stPtr, stWarn := postfixServiceStatePtr(ctx, services)
	out.ServiceState = stPtr
	var warnings []string
	if len(stWarn) > 0 {
		warnings = append(warnings, stWarn...)
	}
	vals, err := QueryPostconf(ctx, postconfKeysPosture)
	if err != nil {
		out.Error = "postconf: " + err.Error()
		out.CollectorWarnings = append(warnings, out.CollectorWarnings...)
		finalizePostfixPostureArrays(out)
		return out
	}
	applyPostconfToPosture(vals, out)
	masterPath := resolveMasterCfPath(vals)
	ins := collectMasterCfInsights(masterPath, &warnings)
	out.SubmissionPortEnabled = ins.SubmissionPortEnabled
	out.ShowqServiceExposed = ins.ShowqServiceExposed
	out.ChrootRatioSummary = ins.ChrootRatioSummary
	out.IsContainerized = shared.HostIsContainerized()
	out.CollectorWarnings = append(warnings, out.CollectorWarnings...)
	finalizePostfixPostureArrays(out)
	return out
}

func applyPostconfToPosture(vals map[string]string, out *payload.PostfixPosture) {
	setStr := func(dst **string, key string) {
		if v := strings.TrimSpace(vals[key]); v != "" {
			t := truncatePostconfValue(key, v)
			*dst = shared.StringPtr(t)
		}
	}
	if v := strings.TrimSpace(vals["mail_version"]); v != "" {
		out.Version = shared.StringPtr(truncatePostconfValue("mail_version", v))
	}
	setStr(&out.ListenAddresses, "inet_interfaces")
	setStr(&out.ListenProtocols, "inet_protocols")
	setStr(&out.Mynetworks, "mynetworks")
	setStr(&out.SmtpdRelayRestrictions, "smtpd_relay_restrictions")
	setStr(&out.RelayDomains, "relay_domains")
	setStr(&out.SmtpdRecipientRestrictions, "smtpd_recipient_restrictions")
	setStr(&out.SmtpdTlsSecurityLevel, "smtpd_tls_security_level")
	setStr(&out.SmtpTlsSecurityLevel, "smtp_tls_security_level")
	setStr(&out.SmtpdTlsProtocols, "smtpd_tls_protocols")
	setStr(&out.SmtpdTlsMandatoryCiphers, "smtpd_tls_mandatory_ciphers")
	out.TlsPreemptCipherlist = postconfBoolPtr(vals["tls_preempt_cipherlist"])
	out.SmtpdSaslAuthEnable = postconfBoolPtr(vals["smtpd_sasl_auth_enable"])
	setStr(&out.SmtpdSaslSecurityOptions, "smtpd_sasl_security_options")
	out.SmtpdTlsAuthOnly = postconfBoolPtr(vals["smtpd_tls_auth_only"])
	setStr(&out.SmtpdSenderRestrictions, "smtpd_sender_restrictions")
	out.SmtpdHeloRequired = postconfBoolPtr(vals["smtpd_helo_required"])
	setStr(&out.SmtpdHeloRestrictions, "smtpd_helo_restrictions")
	setStr(&out.SmtpdSenderLoginMaps, "smtpd_sender_login_maps")
	setStr(&out.SmtpdBanner, "smtpd_banner")
	setStr(&out.SmtpdClientConnectionRateLimit, "smtpd_client_connection_rate_limit")
	setStr(&out.SmtpdClientMessageRateLimit, "smtpd_client_message_rate_limit")
	setStr(&out.SmtpdErrorSleepTime, "smtpd_error_sleep_time")
	setStr(&out.SmtpdHardErrorLimit, "smtpd_hard_error_limit")
	setStr(&out.MessageSizeLimit, "message_size_limit")
	setStr(&out.RunUser, "mail_owner")
}

func postconfBoolPtr(v string) *bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "yes" || s == "y" {
		return shared.BoolPtr(true)
	}
	if s == "no" || s == "n" {
		return shared.BoolPtr(false)
	}
	return nil
}

func finalizePostfixPostureArrays(out *payload.PostfixPosture) {
	if out == nil {
		return
	}
	if out.CollectorWarnings == nil {
		out.CollectorWarnings = []string{}
	}
}

func resolvePostfixBinary() string {
	if p, err := exec.LookPath("postfix"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/postfix", "/usr/bin/postfix"} {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func postfixServiceStatePtr(ctx context.Context, services []payload.ServiceEntry) (*string, []string) {
	s := postfixServiceState(ctx, services)
	if s == "running" || s == "stopped" {
		return shared.StringPtr(s), nil
	}
	return nil, []string{"postfix service_state could not be determined as running or stopped from systemd inventory or systemctl is-active."}
}

func postfixServiceState(ctx context.Context, services []payload.ServiceEntry) string {
	want := map[string]struct{}{"postfix.service": {}}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := systemdutil.MapActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return st
		}
	}
	if st := systemdutil.SystemctlIsActiveState(ctx, "postfix.service"); st == "running" || st == "stopped" {
		return st
	}
	return ""
}
