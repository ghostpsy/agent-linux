//go:build linux

package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergePostgresqlConfIncludeDirStripsTrailingComment(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	confDir := filepath.Join(root, "main")
	if err := os.MkdirAll(filepath.Join(confDir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	mainConf := filepath.Join(confDir, "postgresql.conf")
	// Debian/Ubuntu style: quoted relative path and an inline comment (must not become part of the path).
	body := "include_dir = 'conf.d'\t\t\t# include files ending in '.conf' from:\n"
	if err := os.WriteFile(mainConf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(confDir, "conf.d", "extra.conf")
	if err := os.WriteFile(extra, []byte("listen_addresses = '*'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	settings, _, warnings := mergePostgresqlConf(mainConf)
	if got := strings.TrimSpace(settings["listen_addresses"]); got != "*" {
		t.Fatalf("listen_addresses: got %q want *", got)
	}
	for _, w := range warnings {
		if strings.Contains(w, "include_dir unreadable") {
			t.Fatalf("unexpected warning: %s", w)
		}
	}
}
