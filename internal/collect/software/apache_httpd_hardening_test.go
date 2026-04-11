//go:build linux

package software

import (
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestOptionsLineEnablesIndexes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want bool
	}{
		{"Options Indexes FollowSymLinks", true},
		{"Options FollowSymLinks -Indexes", false},
		{"Options -Indexes +FollowSymLinks", false},
		{"Options All", true},
		{"Options FollowSymLinks", false},
		{"  Options  +Indexes  ", true},
	}
	for _, tc := range cases {
		if got := optionsLineEnablesIndexes(tc.line); got != tc.want {
			t.Fatalf("%q: got %v want %v", tc.line, got, tc.want)
		}
	}
}

func TestApplyApacheMainConfigHardening(t *testing.T) {
	t.Parallel()
	conf := `# sample
TraceEnable Off
SSLProtocol all -SSLv3 -TLSv1 +TLSv1.2
SSLCipherSuite HIGH:!aNULL
AllowOverride None
Options -Indexes +FollowSymLinks
`
	h := &payload.ApacheHardeningHints{}
	applyApacheMainConfigHardening(conf, h)
	if h.TraceEnable != "Off" {
		t.Fatalf("trace: %q", h.TraceEnable)
	}
	if h.SSLProtocolSummary == "" || !strings.Contains(strings.ToLower(h.SSLProtocolSummary), "tlsv1.2") {
		t.Fatalf("ssl protocol: %q", h.SSLProtocolSummary)
	}
	if h.SSLCipherSuiteSummary == "" {
		t.Fatal("expected ssl cipher summary")
	}
	if h.AllowOverrideMain != "None" {
		t.Fatalf("allow override: %q", h.AllowOverrideMain)
	}
	if len(h.OptionsLinesSample) != 1 {
		t.Fatalf("options sample: %#v", h.OptionsLinesSample)
	}
	if h.IndexesInOptionsHint == nil || *h.IndexesInOptionsHint {
		t.Fatalf("indexes hint should be false, got %#v", h.IndexesInOptionsHint)
	}
}
