//go:build linux

package software

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestMarshalApacheHttpdPosture_NoDisallowedSecretPatterns(t *testing.T) {
	t.Parallel()
	falsePtr := false
	p := &payload.ApacheHttpdPosture{
		Detected:       true,
		Version:        "Apache/2.4.52 (Vendor)",
		BinPath:        "/usr/sbin/httpd",
		ServiceState:   "running",
		VhostsSummary:  &payload.ApacheVhostsSummary{VhostCount: 1, ServerNames: []string{"www.example.com"}},
		ListenBindings: []payload.ApacheListenBinding{{Bind: "*", Port: 443}},
		HardeningHints: &payload.ApacheHardeningHints{
			TraceEnable:             "Off",
			SSLProtocolSummary:      "all -SSLv3 +TLSv1.2",
			SSLCipherSuiteSummary:   "HIGH:!aNULL",
			AllowOverrideMain:       "None",
			OptionsLinesSample:      []string{"Options -Indexes +FollowSymLinks"},
			IndexesInOptionsHint:    &falsePtr,
			SecurityRelevantModules: []string{"ssl_module"},
		},
		Error: "vhost dump: (AH00112: Warning: DocumentRoot may be wrong — example only)",
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	banned := []string{
		"begin rsa private",
		"begin private key",
		"-----begin",
		"api_key",
		"apikey",
		"password=",
		"authorization:",
	}
	for _, s := range banned {
		if strings.Contains(lower, s) {
			t.Fatalf("JSON must not contain %q: %s", s, string(raw))
		}
	}
}

func TestParseApacheSDump_ServerNamesExcludeFilesystemPaths(t *testing.T) {
	t.Parallel()
	in := `VirtualHost configuration:
*:80                   is a NameVirtualHost
         default server www.prod.example (/etc/httpd/conf.d/app.conf:10)
         port 80 namevhost www.prod.example (/etc/httpd/conf.d/app.conf:10)
`
	got := parseApacheSDump(in)
	for _, n := range got.serverNames {
		if strings.Contains(n, "/etc/") || strings.Contains(n, "/var/") {
			t.Fatalf("server name should be hostname-like, got %q", n)
		}
	}
}
