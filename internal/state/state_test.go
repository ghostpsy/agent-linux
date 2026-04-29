package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func setStatePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	t.Setenv(envPathOverride, p)
	return p
}

func TestSave_and_Load(t *testing.T) {
	setStatePath(t)
	s := &AgentState{
		MachineUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
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
	if loaded.ScanSeq != s.ScanSeq {
		t.Fatalf("ScanSeq: got %d, want %d", loaded.ScanSeq, s.ScanSeq)
	}
}

func TestLoad_missingFile(t *testing.T) {
	setStatePath(t)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when file does not exist")
	}
}

func TestLoad_invalidJSON(t *testing.T) {
	p := setStatePath(t)
	if err := os.WriteFile(p, []byte("{invalid}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_missingMachineUUID(t *testing.T) {
	p := setStatePath(t)
	data, _ := json.Marshal(AgentState{ScanSeq: 1})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing machine_uuid")
	}
}

func TestSave_WritesMode0600(t *testing.T) {
	p := setStatePath(t)
	s := &AgentState{MachineUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ScanSeq: 0}
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode %#o want %#o", mode, 0o600)
	}
}
