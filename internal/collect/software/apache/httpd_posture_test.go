//go:build linux

package apache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExecutable(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTruncateApacheOut(t *testing.T) {
	t.Parallel()
	if len(truncateApacheOut([]byte("x"))) != 1 {
		t.Fatal("short input should be unchanged")
	}
	over := make([]byte, apacheCmdMaxOutput+5000)
	for i := range over {
		over[i] = 'z'
	}
	got := truncateApacheOut(over)
	if len(got) != apacheCmdMaxOutput {
		t.Fatalf("want len %d got %d", apacheCmdMaxOutput, len(got))
	}
}

func TestTrimApacheErr_UsesStderrWhenEmpty(t *testing.T) {
	t.Parallel()
	err := trimApacheErr("version: ", os.ErrPermission, nil)
	if err == "" || !strings.HasPrefix(err, "version: ") {
		t.Fatalf("got %q", err)
	}
}

func TestCollectApacheHttpdPostureWithBinary_VersionExitError(t *testing.T) {
	script := `#!/bin/sh
echo synthetic failure on stderr
exit 1
`
	bin := writeExecutable(t, "fake-httpd", script)
	out := collectApacheHttpdPostureWithBinary(context.Background(), bin, bin, nil, nil)
	if out == nil || !out.Detected {
		t.Fatal("expected detected posture")
	}
	if !strings.HasPrefix(out.Error, "version: ") {
		t.Fatalf("expected version error prefix, got %q", out.Error)
	}
}

func TestCollectApacheHttpdPostureWithBinary_ParentContextTimeout(t *testing.T) {
	// exec so the child process is sleep(1), not a shell wrapper—CommandContext can terminate it reliably.
	script := `#!/bin/sh
exec sleep 60
`
	bin := writeExecutable(t, "slow-httpd", script)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	out := collectApacheHttpdPostureWithBinary(ctx, bin, bin, nil, nil)
	if out == nil || out.Error == "" {
		t.Fatal("expected timeout or cancellation error on -v")
	}
	if !strings.Contains(out.Error, "version: ") {
		t.Fatalf("expected version-scoped error, got %q", out.Error)
	}
}

func TestCollectApacheHttpdPostureWithBinary_StubScriptSuccess(t *testing.T) {
	script := `#!/bin/sh
if [ "$1" = "-v" ]; then
  echo "Server version: Apache/2.4.test (StubOS)"
  exit 0
fi
if [ "$1" = "-S" ]; then
  printf '%s\n' "VirtualHost configuration:" \
    "*:80                   is a NameVirtualHost" \
    "         default server stub.example.test (/etc/httpd/conf.d/vhost.conf:1)" \
    "         port 80 namevhost stub.example.test (/etc/httpd/conf.d/vhost.conf:1)"
  exit 0
fi
exit 1
`
	bin := writeExecutable(t, "stub-httpd", script)
	out := collectApacheHttpdPostureWithBinary(context.Background(), bin, bin, nil, nil)
	if out == nil || out.Error != "" {
		t.Fatalf("unexpected error: %+v", out)
	}
	if out.Version == nil || !strings.Contains(*out.Version, "Apache/2.4.test") {
		t.Fatalf("version: %v", out.Version)
	}
	if out.VhostsSummary == nil || out.VhostsSummary.VhostCount < 1 {
		t.Fatalf("vhosts: %+v", out.VhostsSummary)
	}
	if len(out.ListenBindings) != 1 || out.ListenBindings[0].Port != 80 {
		t.Fatalf("bindings: %+v", out.ListenBindings)
	}
}

func TestCollectApacheHttpdPostureWithBinary_StubVhostDumpFails(t *testing.T) {
	script := `#!/bin/sh
if [ "$1" = "-v" ]; then
  echo "Server version: Apache/2.4.test (StubOS)"
  exit 0
fi
if [ "$1" = "-S" ]; then
  echo permission denied reading config
  exit 1
fi
exit 1
`
	bin := writeExecutable(t, "stub-httpd2", script)
	out := collectApacheHttpdPostureWithBinary(context.Background(), bin, bin, nil, nil)
	if out == nil || !strings.Contains(out.Error, "vhost dump:") {
		t.Fatalf("expected vhost dump error, got %+v", out)
	}
	if out.Version == nil || *out.Version == "" {
		t.Fatal("version should be set before -S fails")
	}
	if out.VhostsSummary != nil {
		t.Fatal("vhosts should be absent when -S fails")
	}
}
