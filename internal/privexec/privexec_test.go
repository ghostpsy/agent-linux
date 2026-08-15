//go:build linux

package privexec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// declareForTest adds a command to the registry for one test only.
func declareForTest(t *testing.T, id ID, c Command) {
	t.Helper()
	if _, exists := registry[id]; exists {
		t.Fatalf("test id %q collides with a real declared command", id)
	}
	registry[id] = c
	t.Cleanup(func() { delete(registry, id) })
}

// The security property this whole package exists for: if a command is not
// declared in the registry, the agent must not be able to run it as root.
func TestRunRefusesUndeclaredID(t *testing.T) {
	_, err := Run(context.Background(), ID("definitely-not-declared"))

	if err == nil {
		t.Fatal("expected Run to refuse an undeclared command ID, got nil error")
	}
	if !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("expected ErrNotDeclared, got: %v", err)
	}
}

func TestRunExecutesADeclaredCommandAndCapturesStdout(t *testing.T) {
	declareForTest(t, ID("test:echo"), Command{Binary: "/bin/echo", Args: []string{"hello"}})

	res, err := Run(context.Background(), ID("test:echo"))

	if err != nil {
		t.Fatalf("expected the declared command to run, got error: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello" {
		t.Fatalf("expected stdout %q, got %q", "hello", got)
	}
}

// Two collectors force LC_ALL=C so the command answers in a language their
// parser understands (see internal/collect/network/services.go). sudo deletes
// the environment by default, so a declared command must carry its own or the
// parsing breaks silently on any server that is not set to English.
func TestRunAppliesTheDeclaredEnvironment(t *testing.T) {
	declareForTest(t, ID("test:env"), Command{
		Binary: "/usr/bin/env",
		Env:    []string{"LC_ALL=C"},
	})

	res, err := Run(context.Background(), ID("test:env"))

	if err != nil {
		t.Fatalf("expected the declared command to run, got error: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "LC_ALL=C") {
		t.Fatalf("expected the declared environment to reach the command, got: %q", res.Stdout)
	}
}
