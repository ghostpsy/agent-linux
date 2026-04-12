//go:build linux

package mysql

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestMysqlBindImpliesAllInterfaces(t *testing.T) {
	t.Parallel()
	if !mysqlBindImpliesAllInterfaces("0.0.0.0") || !mysqlBindImpliesAllInterfaces("::") || !mysqlBindImpliesAllInterfaces("*") {
		t.Fatal("expected all-interfaces binds")
	}
	if mysqlBindImpliesAllInterfaces("127.0.0.1") {
		t.Fatal("localhost should not imply all interfaces")
	}
}

func TestCollectMysqlPosture_StubMysqld(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "mysqld  Ver 8.0.35 for Linux on x86_64 (MySQL Community Server - GPL)"
  exit 0
fi
exit 1
`
	p := filepath.Join(dir, "mysqld")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := CollectMysqlPosture(context.Background(), nil)
	if out == nil || !out.Detected {
		t.Fatal("expected detected posture")
	}
	if out.Engine != "mysql" {
		t.Fatalf("engine %q", out.Engine)
	}
	if out.Version == nil || *out.Version == "" {
		t.Fatalf("version %#v", out.Version)
	}
	if len(out.LimitedWithoutSQLAccess) == 0 {
		t.Fatal("expected limited_without_sql_access")
	}
	if out.CollectorWarnings == nil {
		t.Fatal("collector_warnings slice required")
	}
}

func TestMysqlServiceState_FromInventory(t *testing.T) {
	t.Parallel()
	services := []payload.ServiceEntry{{Name: "mariadb.service", ActiveState: "active"}}
	st := mysqlServiceState(context.Background(), services)
	if st != "running" {
		t.Fatalf("got %q", st)
	}
}
