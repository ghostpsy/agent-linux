//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The heartbeat is what lets the dashboard tell a switched-off server apart
// from a broken agent. It has to carry enough to be useful and nothing more.
func TestHeartbeatSendsTheMachineAndTheAgentVersion(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postHeartbeat(context.Background(), srv.URL, "tok-123", heartbeatBody{
		MachineUUID:  "11111111-2222-3333-4444-555555555555",
		AgentVersion: "2.0.0",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth != "Bearer tok-123" {
		t.Errorf("expected the agent token as a bearer, got %q", auth)
	}
	if got["machine_uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("machine_uuid missing or wrong: %v", got)
	}
	if got["agent_version"] != "2.0.0" {
		t.Errorf("agent_version missing or wrong: %v", got)
	}
}

// Drift means the agent has quietly lost part of its privileges. It must reach
// the dashboard, because the person who can fix it is not reading this
// server's logs.
func TestHeartbeatReportsSudoRuleDrift(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	drifted := false
	err := postHeartbeat(context.Background(), srv.URL, "tok", heartbeatBody{
		MachineUUID:     "m-1",
		SudoRuleCurrent: &drifted,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["sudo_rule_current"] != false {
		t.Errorf("expected sudo_rule_current false to be sent, got: %v", got)
	}
}

// An agent that cannot tell must say nothing rather than claim the rule is
// fine. Absent and false are different answers.
func TestHeartbeatOmitsDriftWhenItIsUnknown(t *testing.T) {
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		raw = string(b[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postHeartbeat(context.Background(), srv.URL, "tok", heartbeatBody{MachineUUID: "m-1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(raw, "sudo_rule_current") {
		t.Errorf("an unknown drift state must not be sent at all, got: %s", raw)
	}
}

// A failing heartbeat is reported so the loop can log it, but the loop already
// treats it as non-fatal — a machine must not go silent because one small
// request failed.
func TestHeartbeatReportsAServerRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := postHeartbeat(context.Background(), srv.URL, "bad", heartbeatBody{MachineUUID: "m-1"})

	if err == nil {
		t.Fatal("expected a refused heartbeat to be reported")
	}
}
