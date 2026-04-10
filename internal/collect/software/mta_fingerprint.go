//go:build linux

package software

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const mtaTimeout = 12 * time.Second

// CollectMtaFingerprint detects Postfix / Exim / Sendmail and collects bounded relay hints.
func CollectMtaFingerprint(ctx context.Context) *payload.MtaFingerprint {
	out := &payload.MtaFingerprint{}
	if _, err := exec.LookPath("postfix"); err == nil || fileExists("/usr/sbin/postfix") || fileExists("/usr/bin/postfix") {
		out.DetectedMta = "postfix"
		fillPostfix(out)
		return out
	}
	eximPaths := []string{"/etc/exim4/exim4.conf.template", "/etc/exim/exim.conf", "/usr/local/etc/exim/exim.conf"}
	for _, p := range eximPaths {
		if fileExists(p) {
			out.DetectedMta = "exim"
			out.EximConfigPath = p
			b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
			if err == nil {
				out.EximRelayDomainsHintSample = grepLinesContaining(string(b), "relay_domains", 8, 256)
				if len(out.EximRelayDomainsHintSample) == 0 {
					out.EximRelayDomainsHintSample = grepLinesContaining(string(b), "dc_relay_domains", 8, 256)
				}
			}
			return out
		}
	}
	sendmailCf := "/etc/mail/sendmail.cf"
	if st, err := os.Stat(sendmailCf); err == nil && !st.IsDir() {
		t := true
		out.DetectedMta = "sendmail"
		out.SendmailCfPathPresent = &t
		b, err := shared.ReadFileBounded(sendmailCf, shared.DefaultConfigFileReadLimit)
		if err == nil {
			lines := nonCommentLines(string(b))
			out.SendmailLinesSample = capStringSlice(lines, 8, 256)
		}
		return out
	}
	out.DetectedMta = "none"
	return out
}

func fillPostfix(out *payload.MtaFingerprint) {
	ctx, cancel := context.WithTimeout(context.Background(), mtaTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "postconf", "-n")
	raw, err := cmd.Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
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
		switch k {
		case "inet_interfaces":
			out.PostfixInetInterfaces = shared.TruncateRunes(v, 256)
		case "mynetworks_style":
			out.PostfixMynetworksStyle = shared.TruncateRunes(v, 128)
		case "smtpd_recipient_restrictions":
			t := true
			out.PostfixSmtpdRecipientRestrictionsPresent = &t
		}
	}
}

func grepLinesContaining(body, substr string, maxLines, maxRunes int) []string {
	sub := strings.ToLower(substr)
	var out []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(strings.ToLower(t), sub) {
			out = append(out, shared.TruncateRunes(t, maxRunes))
			if len(out) >= maxLines {
				break
			}
		}
	}
	return out
}
