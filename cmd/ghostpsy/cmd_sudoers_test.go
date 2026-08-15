//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"
)

// A host with none of the declared software needs no privilege at all. Saying
// that plainly matters: a file with a header and no rules looks like something
// went wrong, and the user cannot tell an empty grant from a broken generator.
func TestSudoersCommandSaysSoWhenNothingNeedsGranting(t *testing.T) {
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sudoers command failed: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "NOPASSWD:") {
		t.Skip("this host has some of the declared software installed; nothing to assert")
	}
	if !strings.Contains(got, "nothing on this server needs") {
		t.Fatalf("expected a plain explanation that no privilege is needed, got:\n%s", got)
	}
}

// The file has to say where it came from and how to install it, because the
// person reading it did not generate it and needs to know it is ours.
func TestSudoersCommandExplainsWhereTheFileGoes(t *testing.T) {
	cmd := newSudoersCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sudoers command failed: %v", err)
	}

	got := out.String()
	for _, want := range []string{"/etc/sudoers.d/ghostpsy", "visudo"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the header to mention %q, got:\n%s", want, got)
		}
	}
}
