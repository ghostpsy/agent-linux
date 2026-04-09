//go:build linux

package logging

import "testing"

func TestUnitActiveBoolFromString(t *testing.T) {
	if unitActiveBoolFromString("") != nil {
		t.Fatal("empty -> nil")
	}
	if b := unitActiveBoolFromString("active"); b == nil || !*b {
		t.Fatal("active -> true")
	}
	if b := unitActiveBoolFromString("inactive"); b == nil || *b {
		t.Fatal("inactive -> false")
	}
	if b := unitActiveBoolFromString("failed"); b == nil || *b {
		t.Fatal("failed -> false")
	}
}
