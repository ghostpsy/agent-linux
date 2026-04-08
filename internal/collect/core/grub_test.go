//go:build linux

package core

import "testing"

func TestParseGrubQuotedValue(t *testing.T) {
	if v := parseGrubQuotedValue(`"quiet splash"`); v != "quiet splash" {
		t.Fatalf("got %q", v)
	}
	if v := parseGrubQuotedValue(`'foo bar'`); v != "foo bar" {
		t.Fatalf("got %q", v)
	}
	if v := parseGrubQuotedValue(`unquoted`); v != "unquoted" {
		t.Fatalf("got %q", v)
	}
}
