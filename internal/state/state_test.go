package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// A scan runs as a child process and writes this file itself. The daemon must
// not put back the copy it read when it started.
//
// This is the bug it was written for: the API had scans 1 and 2, the machine's
// own file said 0, and every scan after that was refused as a duplicate. The
// daemon had saved its start-up copy to record the time of the last scan, and
// the scan sequence went back with it.
func TestRecordLastScanKeepsWhatTheScanWrote(t *testing.T) {
	setStatePath(t)
	if err := Save(&AgentState{MachineUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ScanSeq: 0}); err != nil {
		t.Fatal(err)
	}

	// What the daemon holds: the file as it was when it started.
	stale, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// What the scan wrote while the daemon was busy.
	fresh := *stale
	fresh.ScanSeq = 2
	if err := Save(&fresh); err != nil {
		t.Fatal(err)
	}

	if err := RecordLastScan(time.Unix(1788268597, 0)); err != nil {
		t.Fatalf("RecordLastScan: %v", err)
	}

	after, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.ScanSeq != 2 {
		t.Fatalf("the scan sequence went backwards to %d; the scan had written 2", after.ScanSeq)
	}
	if after.LastScanAt != 1788268597 {
		t.Fatalf("LastScanAt: got %d, want 1788268597", after.LastScanAt)
	}
	// The daemon's own copy is untouched, which is the whole reason it must not be saved.
	if stale.ScanSeq != 0 {
		t.Fatalf("the test is not reproducing the bug: the stale copy says %d", stale.ScanSeq)
	}
}
