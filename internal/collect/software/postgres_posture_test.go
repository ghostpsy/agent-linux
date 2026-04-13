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
	out := CollectPostgresPosture(context.Background(), nil, nil)
	if out == nil || !out.Detected {
		t.Fatal("expected detected posture")
	}
	if out.Version == nil || !strings.Contains(*out.Version, "PostgreSQL") {
		t.Fatalf("version %v", out.Version)
	}
}

func TestPostgresServiceState_FromInventory(t *testing.T) {
	t.Parallel()
	services := []payload.ServiceEntry{{Name: "postgresql@16-main.service", ActiveState: "active"}}
	out := CollectPostgresPosture(context.Background(), services, nil)
	if out == nil || out.ServiceState == nil || *out.ServiceState != "running" {
		t.Fatalf("got %v", out.ServiceState)
	}
}
