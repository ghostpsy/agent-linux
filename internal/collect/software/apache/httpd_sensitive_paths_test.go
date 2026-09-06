//go:build linux

package apache

import "testing"

// stockUbuntuApache is the shape of a default Debian/Ubuntu apache, in the order
// this walker merges it: apache2.conf, then mods-enabled, then conf-enabled.
//
// /server-status is restricted here, exactly as the distribution ships it.
const stockUbuntuApache = `
# ---- apache2.conf ----
<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

# ---- mods-enabled/status.conf ----
<IfModule mod_status.c>
	<Location /server-status>
		SetHandler server-status
		Require local
		#Require ip 192.0.2.0/24
	</Location>
	ExtendedStatus On
</IfModule>

# ---- conf-enabled/serve-cgi-bin.conf ----
<IfModule mod_alias.c>
	<Directory "/usr/lib/cgi-bin">
		AllowOverride None
		Require all granted
	</Directory>
</IfModule>
`

// TestAStockApacheIsNotReportedAsExposed is the false positive this file exists
// for.
//
// The old check was one regex with (?s) set, so its dot crossed newlines,
// </Location> and the end of the file. Every config the walker merges is
// concatenated, so on a real Ubuntu 14.04 host it paired the
// <Location /server-status> in mods-enabled/status.conf with the
// "Require all granted" in conf-enabled/serve-cgi-bin.conf, two files later, and
// raised a P1 saying an admin page restricted by "Require local" was open to the
// world. Every default apache install would have been flagged.
func TestAStockApacheIsNotReportedAsExposed(t *testing.T) {
	got := apacheSensitivePathsUnrestricted(stockUbuntuApache)
	if len(got) != 0 {
		t.Fatalf("a correctly restricted /server-status was reported as exposed: %v", got)
	}
}

// And the finding must still fire when the path really is open.
func TestAnOpenServerStatusIsStillReported(t *testing.T) {
	conf := `
<Location /server-status>
	SetHandler server-status
	Require all granted
</Location>
`
	got := apacheSensitivePathsUnrestricted(conf)
	if len(got) != 1 || got[0] != "/server-status" {
		t.Fatalf("got %v, want [/server-status]", got)
	}
}

func TestTheOldAllowFromAllSpellingIsStillRead(t *testing.T) {
	conf := `
<Location /server-info>
	SetHandler server-info
	Order deny,allow
	Allow from all
</Location>
`
	got := apacheSensitivePathsUnrestricted(conf)
	if len(got) != 1 || got[0] != "/server-info" {
		t.Fatalf("got %v, want [/server-info]", got)
	}
}

// A line behind a # is how these grants are usually switched off.
func TestACommentedGrantIsNotAGrant(t *testing.T) {
	conf := `
<Location /balancer-manager>
	SetHandler balancer-manager
	#Require all granted
	Require local
</Location>
`
	if got := apacheSensitivePathsUnrestricted(conf); len(got) != 0 {
		t.Fatalf("a commented grant was read as live: %v", got)
	}
}

// One open block must not open a different path that happens to sit near it.
func TestOneOpenBlockDoesNotOpenItsNeighbour(t *testing.T) {
	conf := `
<Location /server-status>
	Require local
</Location>
<Location /server-info>
	Require all granted
</Location>
`
	got := apacheSensitivePathsUnrestricted(conf)
	if len(got) != 1 || got[0] != "/server-info" {
		t.Fatalf("got %v, want only [/server-info]", got)
	}
}
