//go:build linux

package apache

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestMarshalApacheHttpdPosture_NoDisallowedSecretPatterns(t *testing.T) {
	t.Parallel()
	falsePtr := false
	ver := "Apache/2.4.52 (Vendor)"
	st := "running"
	p := &payload.ApacheHttpdPosture{
		Detected:                     true,
		BinPath:                      "/usr/sbin/httpd",
		Version:                      &ver,
		ServiceState:                 &st,
		ListenBindings:               []payload.ApacheListenBinding{{Bind: "*", Port: 443}},
		ListenBindingDiscrepancies:   []string{},
		SSLModuleLoaded:              shared.BoolPtr(true),
		SSLProtocol:                  strPtr("all -SSLv3 +TLSv1.2"),
		SSLCipherSuite:               strPtr("HIGH:!aNULL"),
		HstsHeader:                   nil,
		HTTPToHTTPSRedirect:          shared.BoolPtr(false),
		RiskyModulesLoaded:           []string{},
		ProtectiveModulesMissing:     []string{"evasive20_module"},
		ServerTokens:                 strPtr("Prod"),
		ServerSignature:              strPtr("Off"),
		TraceEnabled:                 &falsePtr,
		SensitivePathsUnrestricted:   []string{},
		IndexesEnabledPaths:          []string{},
		FollowSymlinksUnrestrictedPaths: []string{},
		AllowOverrideAllPaths:        []string{},
		MissingSecurityHeaders:       []string{"Content-Security-Policy"},
		RunUser:                      strPtr("www-data"),
		DocrootWorldWritable:         shared.BoolPtr(false),
		IsContainerized:              shared.BoolPtr(false),
		OpenForwardProxy:             nil,
		CollectorWarnings:            []string{},
		VhostsSummary:                &payload.ApacheVhostsSummary{VhostCount: 1, ServerNames: []string{"www.example.com"}},
		Error:                        "vhost dump: (AH00112: Warning: DocumentRoot may be wrong — example only)",
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
