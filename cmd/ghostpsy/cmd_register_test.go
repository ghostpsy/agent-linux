//go:build linux

package main

import "testing"

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
