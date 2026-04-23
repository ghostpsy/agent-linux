package payload

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Issue #137: agent_version is persisted on every ingest so the backend
// can gate behavior on agent age without asking the agent to self-report
// via a separate endpoint.
func TestV1_AgentVersionSerializesUnderAgentVersionKey(t *testing.T) {
	t.Parallel()
	p := V1{
		SchemaVersion: 1,
		MachineUUID:   "m",
		ScanSeq:       1,
		AgentVersion:  "1.2.3",
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"agent_version":"1.2.3"`) {
		t.Fatalf("expected agent_version in payload, got: %s", raw)
	}
}

func TestV1_AgentVersionOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	// Empty version must not leak into the payload — older agents built
	// without the ldflags should still serialize cleanly.
	p := V1{SchemaVersion: 1, MachineUUID: "m", ScanSeq: 1}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"agent_version"`) {
		t.Fatalf("expected agent_version to be omitted when empty, got: %s", raw)
	}
}

func TestAgentUtcRFC3339_utcFormat(t *testing.T) {
	t.Parallel()
	ts := time.Date(2025, 6, 15, 14, 30, 45, 0, time.UTC)
	got := AgentUtcRFC3339(ts)
	want := "2025-06-15T14:30:45Z"
	if got != want {
		t.Fatalf("AgentUtcRFC3339: got %q, want %q", got, want)
	}
}

func TestAgentUtcRFC3339_convertsLocalToUTC(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC+5", 5*60*60)
	ts := time.Date(2025, 6, 15, 19, 30, 0, 0, loc)
	got := AgentUtcRFC3339(ts)
	want := "2025-06-15T14:30:00Z"
	if got != want {
		t.Fatalf("AgentUtcRFC3339: got %q, want %q", got, want)
	}
}

func TestAgentUtcRFC3339_zeroTime(t *testing.T) {
	t.Parallel()
	got := AgentUtcRFC3339(time.Time{})
	want := "0001-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("AgentUtcRFC3339(zero): got %q, want %q", got, want)
	}
}
