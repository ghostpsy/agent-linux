//go:build linux

package postfix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogicalPostfixMasterCfLines_ContinuationAndComments(t *testing.T) {
	t.Parallel()
	raw := `# comment line
smtp       inet  n       -       y       -       -       smtpd
  -o smtpd_tls_security_level=may
pickup    unix  n       -       n       60      1       pickup
`
	lines := LogicalMasterCfLines(raw)
	var joined string
	for _, ln := range lines {
		joined += ln + "\n"
	}
	if !strings.Contains(joined, "smtpd_tls_security_level=may") {
		t.Fatalf("continuation not merged: %q", joined)
	}
	if strings.Contains(joined, "# comment") {
		t.Fatalf("comment should be dropped: %q", joined)
	}
}

func TestCollectPostfixMasterCfInsights_SubmissionAndChroot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "master.cf")
	raw := "submission inet n - n - - smtpd\nsmtp inet n - y - - smtpd\n"
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var w []string
	ins := collectMasterCfInsights(p, &w)
	if ins.SubmissionPortEnabled == nil || !*ins.SubmissionPortEnabled {
		t.Fatalf("want submission true, got %#v", ins.SubmissionPortEnabled)
	}
	if ins.ChrootRatioSummary == nil || *ins.ChrootRatioSummary != "1/2 services chrooted" {
		t.Fatalf("chroot ratio %#v", ins.ChrootRatioSummary)
	}
}
