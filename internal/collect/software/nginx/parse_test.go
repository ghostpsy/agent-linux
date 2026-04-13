//go:build linux

package nginx

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseNginxVersionLine(t *testing.T) {
	t.Parallel()
	in := "nginx version: nginx/1.24.0 (Ubuntu)\n"
	got := parseNginxVersionLine(in)
	if got != "nginx/1.24.0 (Ubuntu)" {
		t.Fatalf("parseNginxVersionLine: got %q", got)
	}
}

func TestParseNginxSecurityRelevantModules_TargetedAndSanitized(t *testing.T) {
	t.Parallel()
	in := "configure arguments: --prefix=/usr --with-pcre --with-cc-opt=-O2 --with-http_ssl_module --add-dynamic-module=/build/ngx/modsecurity.so\n"
	got := parseNginxSecurityRelevantModules(in)
	if len(got) != 2 {
		t.Fatalf("modules: want 2 got %v", got)
	}
	var hasSSL, hasDyn bool
	for _, s := range got {
		if s == "--with-http_ssl_module" {
			hasSSL = true
		}
		if s == "--add-dynamic-module=modsecurity.so" {
			hasDyn = true
		}
	}
	if !hasSSL || !hasDyn {
		t.Fatalf("modules: want ssl flag + sanitized dynamic module, got %v", got)
	}
}

func TestParseNginxSecurityRelevantModules_DropsNonSecurityWith(t *testing.T) {
	t.Parallel()
	in := "configure arguments: --with-pcre --with-zlib --with-file-aio\n"
	got := parseNginxSecurityRelevantModules(in)
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

func TestParseNginxTestDump_ListenAndServerName(t *testing.T) {
	t.Parallel()
	in := `
http { server_tokens off;
  server {
    listen 80;
    listen [::]:443 ssl http2;
    listen 127.0.0.1:8080;
    server_name www.example.com;
  }
}
`
	a := parseNginxTestDump(in)
	if a.serverBlockCount != 1 {
		t.Fatalf("server blocks: want 1 got %d", a.serverBlockCount)
	}
	if len(a.serverNames) != 1 || a.serverNames[0] != "www.example.com" {
		t.Fatalf("server names: got %#v", a.serverNames)
	}
	wantPorts := map[int]bool{80: false, 443: false, 8080: false}
	for _, k := range a.listenKeys {
		wantPorts[k.port] = true
		if k.port == 443 && !k.ssl {
			t.Fatalf("443 should be ssl listen")
		}
	}
	for p, ok := range wantPorts {
		if !ok {
			t.Fatalf("missing port %d in %#v", p, a.listenKeys)
		}
	}
}

func TestParseNginxTestDump_HardeningHints(t *testing.T) {
	t.Parallel()
	in := `
http {
  server_tokens off;
  limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
  server {
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_tickets off;
    ssl_stapling on;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Content-Security-Policy "default-src 'self'";
    client_max_body_size 1m;
    limit_req zone=one burst=5;
    if ($request_method !~ ^(GET|HEAD|POST)$) { return 444; }
    autoindex on;
  }
}
`
	a := parseNginxTestDump(in)
	if summarizeServerTokens(a.hardening.serverTokensModes) != "off" {
		t.Fatalf("server_tokens: got %q", summarizeServerTokens(a.hardening.serverTokensModes))
	}
	tlsSum, leg := summarizeTlsProtocols(a.hardening.sslProtocolTokens)
	if tlsSum == "" || leg == nil || *leg {
		t.Fatalf("tls: summary=%q legacy=%v", tlsSum, leg)
	}
	if summarizeBoolModes(a.hardening.sslPreferModes) != "on" || summarizeBoolModes(a.hardening.sslSessionTicketModes) != "off" {
		t.Fatalf(
			"ssl toggles: prefer=%q tickets=%q",
			summarizeBoolModes(a.hardening.sslPreferModes),
			summarizeBoolModes(a.hardening.sslSessionTicketModes),
		)
	}
	st := summarizeSslStapling(a.hardening.sslStaplingModes)
	if st == nil || !*st {
		t.Fatalf("stapling: %v", st)
	}
	if !a.hardening.rateLimitingSeen || !a.hardening.clientLimitsSeen || !a.hardening.httpMethodRestrictSeen || !a.hardening.autoindexOnSeen {
		t.Fatalf(
			"flags: rl=%v buf=%v meth=%v ai=%v",
			a.hardening.rateLimitingSeen,
			a.hardening.clientLimitsSeen,
			a.hardening.httpMethodRestrictSeen,
			a.hardening.autoindexOnSeen,
		)
	}
	for _, want := range []string{"x_frame_options", "strict_transport_security", "content_security_policy"} {
		if _, ok := a.hardening.securityHeaderNames[want]; !ok {
			t.Fatalf("headers: missing %q in %v", want, securityHeaderList(a.hardening.securityHeaderNames))
		}
	}
}

func TestParseNginxTestDump_LegacyTls(t *testing.T) {
	t.Parallel()
	in := `server { ssl_protocols TLSv1.1 TLSv1.2; }`
	a := parseNginxTestDump(in)
	_, leg := summarizeTlsProtocols(a.hardening.sslProtocolTokens)
	if leg == nil || !*leg {
		t.Fatalf("expected legacy TLS detected, got %v", leg)
	}
}

func nginxDumpAnalysisLeakString(a nginxDumpAnalysis) string {
	parts := append([]string{}, a.serverNames...)
	for _, lk := range a.listenKeys {
		parts = append(parts, lk.bind, strconv.Itoa(lk.port))
	}
	parts = append(parts, a.hardening.sslProtocolTokens...)
	for k := range a.hardening.securityHeaderNames {
		parts = append(parts, k)
	}
	return strings.Join(parts, "\x00")
}

func TestParseNginxTestDump_SkipsSecretLines(t *testing.T) {
	t.Parallel()
	in := "ssl_certificate_key /etc/nginx/supersecret.key;\nlisten 80;\nserver_name safe.example;\n"
	a := parseNginxTestDump(in)
	probe := nginxDumpAnalysisLeakString(a)
	if strings.Contains(strings.ToLower(probe), "supersecret") {
		t.Fatalf("analysis leaked secret: %s", probe)
	}
	if len(a.serverNames) != 1 || a.serverNames[0] != "safe.example" {
		t.Fatalf("server names: %#v", a.serverNames)
	}
}

func TestParseNginxTestDump_MixedServerTokens(t *testing.T) {
	t.Parallel()
	in := "http { server_tokens on; }\nserver { server_tokens off; }\n"
	a := parseNginxTestDump(in)
	if summarizeServerTokens(a.hardening.serverTokensModes) != "mixed" {
		t.Fatalf("want mixed, got %q", summarizeServerTokens(a.hardening.serverTokensModes))
	}
}

func TestParseListenDirective(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, bind string
		port     int
		ssl      bool
		ok       bool
	}{
		{"80", "*", 80, false, true},
		{"443 ssl http2", "*", 443, true, true},
		{"[::]:443 ssl", "[::]", 443, true, true},
		{"127.0.0.1:8080", "127.0.0.1", 8080, false, true},
		{"unix:/var/run/nginx.sock", "", 0, false, false},
	}
	for _, tc := range cases {
		b, p, s, ok := parseListenDirective(tc.in)
		if ok != tc.ok || b != tc.bind || p != tc.port || s != tc.ssl {
			t.Fatalf("parseListenDirective(%q): got bind=%q port=%d ssl=%v ok=%v want bind=%q port=%d ssl=%v ok=%v",
				tc.in, b, p, s, ok, tc.bind, tc.port, tc.ssl, tc.ok)
		}
	}
}
