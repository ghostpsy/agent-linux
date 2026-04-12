//go:build linux

package mysql

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeMysqlMysqldOptionsIncludeAndLastWins(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "my.cnf")
	incPath := filepath.Join(dir, "extra.cnf")
	if err := os.WriteFile(incPath, []byte("[mysqld]\nport=3307\nbind-address=127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	main := "!include " + incPath + "\n[mysqld]\nport=3308\nskip-networking=0\n"
	if err := os.WriteFile(mainPath, []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, primary, pwd, fr, w := mergeMysqlMysqldOptions([]string{mainPath})
	if len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	if fr < 2 {
		t.Fatalf("filesRead=%d", fr)
	}
	if primary == "" {
		t.Fatal("primary path")
	}
	if pwd {
		t.Fatal("password should not be exposed")
	}
	if opts["port"] != "3308" {
		t.Fatalf("last win port want 3308 got %q", opts["port"])
	}
	if opts["bind_address"] != "127.0.0.1" {
		t.Fatalf("bind %q", opts["bind_address"])
	}
	if opts["skip_networking"] != "0" {
		t.Fatalf("skip_networking %q", opts["skip_networking"])
	}
}

func TestMysqlClientPasswordLineSetsExposed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.cnf")
	raw := "[client]\npassword=secret\n[mysqld]\nport=3306\n"
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, pwd, _, w := mergeMysqlMysqldOptions([]string{p})
	if len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	if !pwd {
		t.Fatal("expected password exposed flag")
	}
}
