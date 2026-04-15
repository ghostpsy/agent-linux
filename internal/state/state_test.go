package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSave_and_Load(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s := &AgentState{
		MachineUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ClaimCode:   "test-claim",
		ScanSeq:     7,
	}
	if err := Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.MachineUUID != s.MachineUUID {
		t.Fatalf("MachineUUID: got %q, want %q", loaded.MachineUUID, s.MachineUUID)
	}
	if loaded.ClaimCode != s.ClaimCode {
		t.Fatalf("ClaimCode: got %q, want %q", loaded.ClaimCode, s.ClaimCode)
	}
	if loaded.ScanSeq != s.ScanSeq {
		t.Fatalf("ScanSeq: got %d, want %d", loaded.ScanSeq, s.ScanSeq)
	}
}

func TestLoad_missingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when file does not exist")
	}
}

func TestLoad_invalidJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	p := filepath.Join(dir, ".config", "ghostpsy")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "agent.json"), []byte("{invalid}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_missingMachineUUID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	p := filepath.Join(dir, ".config", "ghostpsy")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(AgentState{ClaimCode: "abc", ScanSeq: 1})
	if err := os.WriteFile(filepath.Join(p, "agent.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing machine_uuid")
	}
}
