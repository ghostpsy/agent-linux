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

func writeStateFile(t *testing.T, raw []byte) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTPSY_STATE_PATH", p)
}

func TestBuildScanPayload_ContextCancelled(t *testing.T) {
	writeStateFile(t, []byte(`{"machine_uuid":"test-uuid-scan","scan_seq":0}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := actionlog.New(false, io.Discard)
	_, _, _, _, err := buildScanPayload(ctx, logger)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestBuildScanPayload_ReturnsJSON(t *testing.T) {
	writeStateFile(t, []byte(`{"machine_uuid":"test-uuid-scan2","scan_seq":0}`))
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
