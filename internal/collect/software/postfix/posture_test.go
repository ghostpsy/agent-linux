//go:build linux

package postfix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestParsePostconfOutput(t *testing.T) {
	t.Parallel()
	raw := "inet_interfaces = loopback-only\nmynetworks_style = host\n"
	m := parsePostconfOutput(raw)
	if m["inet_interfaces"] != "loopback-only" || m["mynetworks_style"] != "host" {
		t.Fatalf("got %#v", m)
	}
}

func TestCollectPostfixPosture_StubBinaries(t *testing.T) {
	dir := t.TempDir()
	postconfScript := fmt.Sprintf(`#!/bin/sh
CONFIG_DIR=%q
for arg in "$@"; do
  case "$arg" in
    config_directory) printf 'config_directory = %%s\n' "$CONFIG_DIR" ;;
    mail_version) echo "mail_version = 3.8.5" ;;
    inet_interfaces) echo "inet_interfaces = loopback-only" ;;
    inet_protocols) echo "inet_protocols = all" ;;
    mynetworks) echo "mynetworks = 127.0.0.0/8" ;;
    smtpd_recipient_restrictions) echo "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination" ;;
    smtpd_relay_restrictions) echo "smtpd_relay_restrictions = permit_mynetworks, defer_unauth_destination" ;;
    smtpd_helo_restrictions) echo "smtpd_helo_restrictions = reject_invalid_helo_hostname" ;;
    smtpd_sender_restrictions) echo "smtpd_sender_restrictions = reject_unknown_sender_domain" ;;
    relay_domains) echo "relay_domains =" ;;
    smtpd_tls_security_level) echo "smtpd_tls_security_level = may" ;;
    smtp_tls_security_level) echo "smtp_tls_security_level = may" ;;
    smtpd_tls_protocols) echo "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1" ;;
    smtpd_tls_mandatory_ciphers) echo "smtpd_tls_mandatory_ciphers = medium" ;;
    tls_preempt_cipherlist) echo "tls_preempt_cipherlist = yes" ;;
    smtpd_sasl_auth_enable) echo "smtpd_sasl_auth_enable = no" ;;
    smtpd_sasl_security_options) echo "smtpd_sasl_security_options = noanonymous" ;;
    smtpd_tls_auth_only) echo "smtpd_tls_auth_only = yes" ;;
    smtpd_helo_required) echo "smtpd_helo_required = yes" ;;
    smtpd_sender_login_maps) echo "smtpd_sender_login_maps =" ;;
    smtpd_banner) echo "smtpd_banner = \$myhostname ESMTP" ;;
    smtpd_client_connection_rate_limit) echo "smtpd_client_connection_rate_limit = 0" ;;
    smtpd_client_message_rate_limit) echo "smtpd_client_message_rate_limit = 0" ;;
    smtpd_error_sleep_time) echo "smtpd_error_sleep_time = 1s" ;;
    smtpd_hard_error_limit) echo "smtpd_hard_error_limit = 20" ;;
    message_size_limit) echo "message_size_limit = 10485760" ;;
    mail_owner) echo "mail_owner = postfix" ;;
  esac
done
`, dir)
	postconfPath := filepath.Join(dir, "postconf")
	if err := os.WriteFile(postconfPath, []byte(postconfScript), 0o700); err != nil {
		t.Fatal(err)
	}
	masterCf := strings.Join([]string{
		"# test master.cf",
		"submission inet n - n - - smtpd",
		"smtp inet n - y - - smtpd",
		"pickup unix n - n 60 1 pickup",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "master.cf"), []byte(masterCf), 0o600); err != nil {
		t.Fatal(err)
	}
	postfixPath := filepath.Join(dir, "postfix")
	if err := os.WriteFile(postfixPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := CollectPostfixPosture(context.Background(), nil)
	if out == nil || !out.Detected {
		t.Fatal("expected detected posture")
	}
	if !strings.HasSuffix(out.BinPath, "postfix") {
		t.Fatalf("bin_path %q", out.BinPath)
	}
	if out.Version == nil || *out.Version != "3.8.5" {
		t.Fatalf("version %#v", out.Version)
	}
	if out.ListenAddresses == nil || *out.ListenAddresses != "loopback-only" {
		t.Fatalf("listen_addresses %#v", out.ListenAddresses)
	}
	if out.Mynetworks == nil || *out.Mynetworks != "127.0.0.0/8" {
		t.Fatalf("mynetworks %#v", out.Mynetworks)
	}
	if out.SubmissionPortEnabled == nil || !*out.SubmissionPortEnabled {
		t.Fatalf("submission_port_enabled %#v", out.SubmissionPortEnabled)
	}
	if out.ChrootRatioSummary == nil || !strings.Contains(*out.ChrootRatioSummary, "/") {
		t.Fatalf("chroot_ratio_summary %#v", out.ChrootRatioSummary)
	}
	if out.TlsPreemptCipherlist == nil || !*out.TlsPreemptCipherlist {
		t.Fatalf("tls_preempt_cipherlist %#v", out.TlsPreemptCipherlist)
	}
	if out.SmtpdSaslAuthEnable == nil || *out.SmtpdSaslAuthEnable {
		t.Fatalf("smtpd_sasl_auth_enable %#v", out.SmtpdSaslAuthEnable)
	}
	if out.CollectorWarnings == nil {
		t.Fatal("collector_warnings must be non-nil slice")
	}
	if out.Error != "" {
		t.Fatalf("unexpected error %q", out.Error)
	}
}

func TestCollectPostfixPosture_PostconfFails(t *testing.T) {
	dir := t.TempDir()
	postconfPath := filepath.Join(dir, "postconf")
	if err := os.WriteFile(postconfPath, []byte("#!/bin/sh\necho oops 1>&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	postfixPath := filepath.Join(dir, "postfix")
	if err := os.WriteFile(postfixPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := CollectPostfixPosture(context.Background(), nil)
	if out == nil || !out.Detected || out.Error == "" || !strings.HasPrefix(out.Error, "postconf: ") {
		t.Fatalf("want postconf error, got %#v", out)
	}
	if out.CollectorWarnings == nil {
		t.Fatal("collector_warnings must be non-nil slice")
	}
}

func TestPostfixServiceState_FromInventory(t *testing.T) {
	t.Parallel()
	services := []payload.ServiceEntry{
		{Name: "postfix.service", ActiveState: "active"},
	}
	st := postfixServiceState(context.Background(), services)
	if st != "running" {
		t.Fatalf("got %q", st)
	}
}
