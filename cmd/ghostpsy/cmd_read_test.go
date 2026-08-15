//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// This subcommand exists to be invoked through sudo. Its whole justification is
// that it returns counts and not file content: granting `cat /etc/shadow`
// instead would pull real password hashes through the agent.
func TestReadShadowPrintsCountsAndNeverAHash(t *testing.T) {
	cmd := newReadShadowCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("read-shadow failed: %v", err)
	}

	var summary map[string]any
	if err := json.Unmarshal(out.Bytes(), &summary); err != nil {
		t.Fatalf("expected JSON, got %q", out.String())
	}
	if _, ok := summary["shadow_readable"]; !ok {
		t.Errorf("expected shadow_readable in the reply, got %v", summary)
	}
	for _, marker := range []string{"$6$", "$y$", "$1$", ":!", "root:"} {
		if strings.Contains(out.String(), marker) {
			t.Fatalf("password material leaked through the boundary: found %q in %s", marker, out.String())
		}
	}
}
