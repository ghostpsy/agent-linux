package payload

import (
	"testing"
	"time"
)

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
