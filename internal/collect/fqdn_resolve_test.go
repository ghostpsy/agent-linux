//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveFqdnFromParts_prefersHostnameFWhenDotted(t *testing.T) {
	got := resolveFqdnFromParts("web", "web.example.com", "other.internal", "example.com")
	if got != "web.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveFqdnFromParts_hostnameFShortFallsBackToA(t *testing.T) {
	got := resolveFqdnFromParts("web", "web", "web.lan web", "")
	if got != "web.lan" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveFqdnFromParts_hostnameFShortFallsBackToDomain(t *testing.T) {
	got := resolveFqdnFromParts("db-prod", "db-prod", "", "corp.example.net")
	if got != "db-prod.corp.example.net" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveFqdnFromParts_skipsLocalhostFqdn(t *testing.T) {
	got := resolveFqdnFromParts("x", "x.localhost", "x.example.com", "")
	if got != "x.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveFqdnFromParts_emptyWhenNoDomainSignal(t *testing.T) {
	if resolveFqdnFromParts("srv", "srv", "srv", "") != "" {
		t.Fatal("expected empty")
	}
	if resolveFqdnFromParts("srv", "srv", "", "-") != "" {
		t.Fatal("expected empty for dns domain -")
	}
}

func TestParseEtcHostnameFqdn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostname")
	if err := os.WriteFile(path, []byte("vm-01.prod.example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := parseEtcHostnameFqdn(path); got != "vm-01.prod.example.org" {
		t.Fatalf("got %q", got)
	}
	if parseEtcHostnameFqdn(filepath.Join(dir, "missing")) != "" {
		t.Fatal("expected empty")
	}
}
