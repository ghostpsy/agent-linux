//go:build linux

package software

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAptGetSimulateDistUpgrade_focalSecurity(t *testing.T) {
	const sample = `Reading package lists...
Inst libc6 [2.31-0ubuntu9.17] (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [arm64])
Inst gpgv [2.2.19-3ubuntu2.4] (2.2.19-3ubuntu2.5 Ubuntu:20.04/focal-updates [arm64])
`
	pending, sec, secNames := parseAptGetSimulateDistUpgrade([]byte(sample))
	if pending != 2 {
		t.Fatalf("pending: got %d", pending)
	}
	if sec != 1 {
		t.Fatalf("security: got %d", sec)
	}
	if len(secNames) != 1 || secNames[0] != "libc6" {
		t.Fatalf("security names (security-only): %#v", secNames)
	}
}

func TestParseAptListUpgradable_bookworm(t *testing.T) {
	const sample = `WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
libssl3/stable-security 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.17-1~deb12u1]
curl/stable-security,stable-security 7.88.1-10+deb12u12 amd64 [upgradable from: 7.88.1-10+deb12u11]
`
	pending, sec, secNames := parseAptListUpgradable([]byte(sample))
	if pending != 2 {
		t.Fatalf("pending: got %d", pending)
	}
	if sec != 2 {
		t.Fatalf("security lines: got %d", sec)
	}
	if len(secNames) != 2 || secNames[0] != "libssl3" || secNames[1] != "curl" {
		t.Fatalf("security names: %#v", secNames)
	}
}

func TestMaxModTimeAptListsDir(t *testing.T) {
	dir := t.TempDir()
	tDir := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	tFile := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	f := filepath.Join(dir, "ubuntu_Release")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f, tFile, tFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dir, tDir, tDir); err != nil {
		t.Fatal(err)
	}
	got, ok := maxModTimeAptListsDir(dir)
	if !ok {
		t.Fatal("expected ok")
	}
	if !got.Equal(tFile.UTC()) {
		t.Fatalf("got %v want %v", got, tFile.UTC())
	}
}

func TestParseAptGetSimulateDistUpgrade_nonEnglishNoInstPrefix(t *testing.T) {
	const sample = `Conf libc6 (2.31-0ubuntu9.18 Debian:11/stable [amd64])
`
	pending, sec, secNames := parseAptGetSimulateDistUpgrade([]byte(sample))
	if pending != 0 || sec != 0 || len(secNames) != 0 {
		t.Fatalf("expected no parse without Inst lines: pending=%d sec=%d secNames=%#v", pending, sec, secNames)
	}
}

func TestParseDnfCheckUpdate_dotArch(t *testing.T) {
	const sample = `Last metadata expiration check: 0:15:36 ago on Mon 01 Jan 2024 12:00:00 PM UTC.
openssl.x86_64                    1:1.1.1k-7.el8_6                    baseos
kernel.x86_64                     4.18.0-513.el8                      baseos
`
	n, names := parseDnfCheckUpdate([]byte(sample))
	if n != 2 {
		t.Fatalf("count: got %d", n)
	}
	if len(names) != 2 || names[0] != "openssl" || names[1] != "kernel" {
		t.Fatalf("names: %#v", names)
	}
}

func TestParseApkUpgradeSimulate_upgrading(t *testing.T) {
	const sample = `(1/3) Upgrading busybox (1.36.1-r20 -> 1.36.1-r21)
(2/3) Upgrading busybox-binsh (1.36.1-r20 -> 1.36.1-r21)
(3/3) Upgrading ssl_client (1.36.1-r20 -> 1.36.1-r21)
OK: 8 MiB in 15 packages
`
	if n := parseApkUpgradeSimulate([]byte(sample)); n != 3 {
		t.Fatalf("pending: got %d want 3", n)
	}
}

func TestParseApkUpgradeSimulate_okOnly(t *testing.T) {
	const sample = `OK: 9 MiB in 14 packages
`
	if n := parseApkUpgradeSimulate([]byte(sample)); n != 0 {
		t.Fatalf("pending: got %d want 0", n)
	}
}

func TestMaxModTimeApkCacheDir(t *testing.T) {
	dir := t.TempDir()
	tDir := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	tFile := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	f := filepath.Join(dir, "APKINDEX.test.tar.gz")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f, tFile, tFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dir, tDir, tDir); err != nil {
		t.Fatal(err)
	}
	got, ok := maxModTimeApkCacheDir(dir)
	if !ok {
		t.Fatal("expected ok")
	}
	if !got.Equal(tFile.UTC()) {
		t.Fatalf("got %v want %v", got, tFile.UTC())
	}
}

func TestParseDnfCheckUpdate_tableColumns(t *testing.T) {
	const sample = `Last metadata expiration check: 0:00:01 ago on Mon 29 Mar 2021 12:00:00 AM UTC.
openssl                    x86_64  1:1.1.1k-7.fc34            updates
`
	n, names := parseDnfCheckUpdate([]byte(sample))
	if n != 1 {
		t.Fatalf("count: got %d", n)
	}
	if len(names) != 1 || names[0] != "openssl" {
		t.Fatalf("names: %#v", names)
	}
}
