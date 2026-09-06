//go:build linux

package identity

import "testing"

// The counts have to come out of `passwd -S -a` exactly as they used to come out
// of /etc/shadow, or swapping to a standard command has cost us the finding.
//
// Real output from a Debian 12 machine. Field order is: account, status, last
// change, min days, max days, warn days, inactive days.
const passwdStatusSample = `root L 2026-08-21 0 99999 7 -1
daemon L 2026-08-21 0 99999 7 -1
bob P 2026-08-21 0 99999 7 -1
carol NP 2026-08-21 0 99999 7 -1
dave P 1970-01-01 0 30 7 -1
`

func TestPasswdStatusCountsLockedAndPasswordless(t *testing.T) {
	got := parsePasswdStatus([]byte(passwdStatusSample))

	if got.locked != 2 {
		t.Errorf("locked: got %d, want 2 (root and daemon are L)", got.locked)
	}
	if got.noPassword != 1 {
		t.Errorf("no password: got %d, want 1 (carol is NP)", got.noPassword)
	}
	if got.total != 5 {
		t.Errorf("total: got %d, want 5", got.total)
	}
}

// An account whose password is older than its maximum age must change it at the
// next login. That is what the old shadow reader called an expiry hint.
func TestPasswdStatusCountsExpiredPasswords(t *testing.T) {
	got := parsePasswdStatus([]byte(passwdStatusSample))

	if got.expired != 1 {
		t.Errorf("expired: got %d, want 1 (dave changed his in 1970 with a 30 day maximum)", got.expired)
	}
}

// A line that is not the shape we expect is skipped, not guessed at. A machine
// with one odd account must still report the other twenty correctly.
func TestPasswdStatusSkipsLinesItDoesNotUnderstand(t *testing.T) {
	got := parsePasswdStatus([]byte("root L 2026-08-21 0 99999 7 -1\ngarbage\n\nbob P\n"))

	if got.total != 1 {
		t.Errorf("total: got %d, want 1 — only the well formed line counts", got.total)
	}
	if got.locked != 1 {
		t.Errorf("locked: got %d, want 1", got.locked)
	}
}

func TestLastlogCountsAccountsNeverUsed(t *testing.T) {
	sample := `Username         Port     From             Latest
root                                       **Never logged in**
bob              pts/0    192.168.64.1     Mon Sep  1 14:22:00 +0000 2026
carol                                      **Never logged in**
`

	if got := countNeverLoggedIn([]byte(sample)); got != 2 {
		t.Errorf("never logged in: got %d, want 2", got)
	}
}

// Zero and "I could not look" are different answers. A reply nothing could be
// read from must not become a machine where no account is locked.
func TestPasswdStatusOfGarbageIsEmptyNotZero(t *testing.T) {
	got := parsePasswdStatus([]byte("sudo: a password is required\n"))

	if got.total != 0 {
		t.Fatalf("total: got %d, want 0 — nothing there was a status line", got.total)
	}
}
