//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRootCommand_UnknownSubcommandReturnsError(t *testing.T) {
	t.Parallel()
	root := newRootCommand()
	root.SetOut(ioDiscardWriter{})
	root.SetErr(ioDiscardWriter{})
	root.SetArgs([]string{"not-a-real-command"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown command in error, got %v", err)
	}
}

func TestNewRootCommand_VersionFlag(t *testing.T) {
	t.Parallel()
	root := newRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected version output")
	}
}

type ioDiscardWriter struct{}

func (ioDiscardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
