//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setAgentConfPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.conf")
	t.Setenv("GHOSTPSY_AGENT_CONFIG_PATH", p)
	return p
}

func TestResolveIngestToken_ReadsAgentConf(t *testing.T) {
	p := setAgentConfPath(t)
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveIngestToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-file" {
		t.Fatalf("got %q want %q", got, "from-file")
	}
}

func TestResolveIngestToken_MissingFileSuggestsRegister(t *testing.T) {
	setAgentConfPath(t)
	_, err := resolveIngestToken()
	if err == nil {
		t.Fatal("expected error when agent.conf is missing")
	}
	if !strings.Contains(err.Error(), "ghostpsy register") {
		t.Fatalf("expected register hint in error, got %v", err)
	}
}

func TestResolveIngestToken_LoosePermsErrors(t *testing.T) {
	p := setAgentConfPath(t)
	if err := os.WriteFile(p, []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveIngestToken(); err == nil {
		t.Fatal("expected loose-permission error")
	}
}
