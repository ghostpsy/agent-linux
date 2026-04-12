//go:build linux

package software

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestListenAddressesImpliesAll(t *testing.T) {
	t.Parallel()
	if !listenAddressesImpliesAll("*") || !listenAddressesImpliesAll("0.0.0.0") {
		t.Fatal("wildcard binds")
	}
	if !listenAddressesImpliesAll("127.0.0.1, ::") {
		t.Fatal("comma list with :: should imply all")
	}
	if listenAddressesImpliesAll("127.0.0.1") {
		t.Fatal("localhost only")
	}
}

func TestAnalyzePgHba(t *testing.T) {
	t.Parallel()
	body := `# TYPE DATABASE USER ADDRESS METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
hostssl all             all             0.0.0.0/0               trust
`
	h := analyzePgHba(body, "/tmp/pg_hba.conf")
	if h == nil {
		t.Fatal("expected hints")
	}
	if h.LocalRuleCount != 1 || h.HostRuleCount != 1 || h.HostsslRuleCount != 1 {
		t.Fatalf("counts local=%d host=%d hostssl=%d", h.LocalRuleCount, h.HostRuleCount, h.HostsslRuleCount)
	}
	if h.TrustMethodCount != 1 || h.PasswordFamilyMethodCount != 1 || h.PeerOrIdentMethodCount != 1 {
		t.Fatalf("methods trust=%d pw=%d peer=%d", h.TrustMethodCount, h.PasswordFamilyMethodCount, h.PeerOrIdentMethodCount)
	}
}

func TestCollectPostgresPosture_StubPostgres(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "-V" ]; then
  echo "postgres (PostgreSQL) 16.2"
  exit 0
fi
exit 1
`
	p := filepath.Join(dir, "postgres")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := CollectPostgresPosture(context.Background(), nil)
	if out == nil || !out.Detected {
		t.Fatal("expected detected posture")
	}
	if !strings.Contains(out.Version, "PostgreSQL") {
		t.Fatalf("version %q", out.Version)
	}
}

func TestPostgresServiceState_FromInventory(t *testing.T) {
	t.Parallel()
	services := []payload.ServiceEntry{{Name: "postgresql@16-main.service", ActiveState: "active"}}
	st := postgresServiceState(context.Background(), services)
	if st != "running" {
		t.Fatalf("got %q", st)
	}
}
