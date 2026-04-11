//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestBuildScanPayload_ContextCancelled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".config", "ghostpsy")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(cfgDir, "agent.json")
	raw := []byte(`{"machine_uuid":"test-uuid-scan","claim_code":"ABC","scan_seq":0}`)
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := actionlog.New(false, io.Discard)
	_, _, _, _, err := buildScanPayload(ctx, logger)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestBuildScanPayload_ReturnsJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".config", "ghostpsy")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(cfgDir, "agent.json")
	raw := []byte(`{"machine_uuid":"test-uuid-scan2","claim_code":"DEF","scan_seq":0}`)
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	logger := actionlog.New(false, io.Discard)
	_, _, _, body, err := buildScanPayload(context.Background(), logger)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if m["schema_version"].(float64) != 1 {
		t.Fatalf("schema_version want 1 got %v", m["schema_version"])
	}
}

func TestWritePayloadPreview_JSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	p := payload.V1{SchemaVersion: 1, MachineUUID: "mid", ScanSeq: 3}
	if err := writePayloadPreview(&buf, p); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("preview output: %v", err)
	}
	if int(decoded["schema_version"].(float64)) != 1 {
		t.Fatalf("schema_version: %v", decoded["schema_version"])
	}
}
