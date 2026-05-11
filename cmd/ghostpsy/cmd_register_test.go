//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRegisterResponse_OK(t *testing.T) {
	body := []byte(`{"job_id":"j","status":"accepted","agent_token":"abc","scan_seq":42}`)
	tok, seq, err := parseRegisterResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc" {
		t.Fatalf("token: got %q", tok)
	}
	if seq != 42 {
		t.Fatalf("scan_seq: got %d", seq)
	}
}

func TestParseRegisterResponse_ScanSeqOmitted(t *testing.T) {
	body := []byte(`{"agent_token":"abc"}`)
	tok, seq, err := parseRegisterResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc" {
		t.Fatalf("token: got %q", tok)
	}
	if seq != 0 {
		t.Fatalf("expected 0 (sentinel) when scan_seq is omitted, got %d", seq)
	}
}

func TestParseRegisterResponse_MissingToken(t *testing.T) {
	if _, _, err := parseRegisterResponse([]byte(`{"scan_seq":1}`)); err == nil {
		t.Fatal("expected error when agent_token is missing")
	}
}

func TestParseRegisterResponse_InvalidJSON(t *testing.T) {
	if _, _, err := parseRegisterResponse([]byte(`not json`)); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestPostRegister_SendsMachineUUIDAndHostname(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_token":"t","machine_uuid":"00000000-0000-0000-0000-000000000000","scan_seq":0}`))
	}))
	defer server.Close()

	resp, err := postRegister(context.Background(), server.URL, "boot", "00000000-0000-0000-0000-000000000000", "prod-original")
	if err != nil {
		t.Fatalf("postRegister: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var parsed map[string]string
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}
	if parsed["machine_uuid"] != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("machine_uuid: got %q", parsed["machine_uuid"])
	}
	if parsed["hostname"] != "prod-original" {
		t.Fatalf("hostname: got %q, expected hostname to be included in register body", parsed["hostname"])
	}
}
