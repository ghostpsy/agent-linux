//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// Measured on docker/debian-13: as an unprivileged user this collector reported
// accounts_locked_count = 0 while the real answer was 25. It set
// shadow_readable=false and an error too, but the count contradicted both.
//
// A count of zero is an answer. "I could not look" is not the same answer, and
// a dashboard cannot tell them apart.
func TestShadowSummaryReportsNoCountsWhenTheFileCannotBeRead(t *testing.T) {
	out := collectShadowFrom(filepath.Join(t.TempDir(), "does-not-exist"))

	if out.Error == "" {
		t.Fatal("expected an error to be recorded when the shadow file cannot be read")
	}
	if out.ShadowReadable {
		t.Fatal("expected shadow_readable to be false")
	}
	if out.AccountsLockedCount != nil {
		t.Fatalf("expected no locked count when the file was never read, got %d", *out.AccountsLockedCount)
	}
	if out.AccountsNoLoginPasswordCount != nil {
		t.Fatalf("expected no no-login count, got %d", *out.AccountsNoLoginPasswordCount)
	}
}

func TestShadowSummaryCountsLockedAccountsWhenTheFileIsReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	content := "root:$6$realhash:19000:0:99999:7:::\n" +
		"daemon:*:19000:0:99999:7:::\n" +
		"bin:!:19000:0:99999:7:::\n" +
		"nobody::19000:0:99999:7:::\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out := collectShadowFrom(path)

	if !out.ShadowReadable {
		t.Fatalf("expected the file to be read, got error %q", out.Error)
	}
	if out.AccountsLockedCount == nil {
		t.Fatal("expected a locked count once the file was read")
	}
	if *out.AccountsLockedCount != 2 {
		t.Fatalf("expected 2 locked accounts (* and !), got %d", *out.AccountsLockedCount)
	}
	if out.AccountsNoLoginPasswordCount == nil || *out.AccountsNoLoginPasswordCount != 1 {
		t.Fatalf("expected 1 account with an empty password, got %v", out.AccountsNoLoginPasswordCount)
	}
}
