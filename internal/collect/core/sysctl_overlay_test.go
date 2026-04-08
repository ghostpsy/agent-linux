//go:build linux

package core

import "testing"

func TestNormalizeSysctlVal_whitespaceEquivalent(t *testing.T) {
	t.Parallel()
	a := normalizeSysctlVal("4 4 1 7")
	b := normalizeSysctlVal("4\t4\t1\t7")
	if a != b {
		t.Fatalf("got %q vs %q", a, b)
	}
	if a != "4 4 1 7" {
		t.Fatalf("canonical form: got %q", a)
	}
}

func TestNormalizeSysctlVal_trimOnly(t *testing.T) {
	t.Parallel()
	if got := normalizeSysctlVal("  1\n"); got != "1" {
		t.Fatalf("got %q", got)
	}
}
