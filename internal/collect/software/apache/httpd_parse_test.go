//go:build linux

package apache

import (
	"testing"
)

func TestParseApacheVersionLine(t *testing.T) {
	t.Parallel()
	in := "Server version: Apache/2.4.52 (Ubuntu)\nServer built:   2022-01-01"
	got := parseApacheVersionLine(in)
	if got != "2.4.52" {
		t.Fatalf("parseApacheVersionLine: got %q", got)
	}
}

func TestParseApacheSDump_DebianStyle(t *testing.T) {
	t.Parallel()
	in := `VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server secure.example.com (/etc/apache2/sites-enabled/default-ssl.conf:1)
         port 443 namevhost secure.example.com (/etc/apache2/sites-enabled/default-ssl.conf:1)
*:80                   is a NameVirtualHost
         default server www.example.com (/etc/apache2/sites-enabled/000-default.conf:1)
         port 80 namevhost www.example.com (/etc/apache2/sites-enabled/000-default.conf:1)
ServerRoot: "/etc/apache2"
`
	p := parseApacheSDump(in)
	if p.vhostCount != 2 {
		t.Fatalf("vhostCount: want 2 got %d", p.vhostCount)
	}
	if len(p.serverNames) != 2 {
		t.Fatalf("server names: want 2 got %d (%v)", len(p.serverNames), p.serverNames)
	}
	if len(p.listenBinds) != 2 {
		t.Fatalf("binds: want 2 got %d", len(p.listenBinds))
	}
}

func TestParseApacheSDump_RHELHttpdStyle(t *testing.T) {
	t.Parallel()
	in := `VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server api.internal.corp (/etc/httpd/conf.d/ssl.conf:1)
         port 443 namevhost api.internal.corp (/etc/httpd/conf.d/ssl.conf:1)
*:80                   is a NameVirtualHost
         default server www.internal.corp (/etc/httpd/conf/httpd.conf:40)
         port 80 namevhost www.internal.corp (/etc/httpd/conf/httpd.conf:40)
ServerRoot: "/etc/httpd"
Main DocumentRoot: "/var/www/html"
`
	p := parseApacheSDump(in)
	if p.vhostCount != 2 {
		t.Fatalf("vhostCount: want 2 got %d", p.vhostCount)
	}
	want := map[string]struct{}{"api.internal.corp": {}, "www.internal.corp": {}}
	for _, n := range p.serverNames {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Fatalf("missing server names, leftover want set: %v got %v", want, p.serverNames)
	}
	if len(p.listenBinds) != 2 {
		t.Fatalf("binds: want 2 got %#v", p.listenBinds)
	}
}

func TestParseApacheSDump_AddressLine(t *testing.T) {
	t.Parallel()
	in := `VirtualHost configuration:
127.0.0.1:8080         app.local (/etc/httpd/conf.d/app.conf:2)
`
	p := parseApacheSDump(in)
	if p.vhostCount < 1 {
		t.Fatalf("vhostCount: want >=1 got %d", p.vhostCount)
	}
	found := false
	for _, b := range p.listenBinds {
		if b.bind == "127.0.0.1" && b.port == 8080 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 127.0.0.1:8080 in binds, got %#v", p.listenBinds)
	}
}
