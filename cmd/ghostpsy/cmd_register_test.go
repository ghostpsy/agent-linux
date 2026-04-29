//go:build linux

package main

import (
	"testing"
)

func TestExtractAgentToken_OK(t *testing.T) {
	body := []byte(`{"job_id":"j","status":"accepted","agent_token":"abc123"}`)
	got, err := extractAgentToken(body)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc123" {
		t.Fatalf("got %q want %q", got, "abc123")
	}
}

func TestExtractAgentToken_MissingField(t *testing.T) {
	body := []byte(`{"job_id":"j","status":"accepted"}`)
	_, err := extractAgentToken(body)
	if err == nil {
		t.Fatal("expected error when agent_token is missing")
	}
}

func TestExtractAgentToken_InvalidJSON(t *testing.T) {
	body := []byte(`not json`)
	_, err := extractAgentToken(body)
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
