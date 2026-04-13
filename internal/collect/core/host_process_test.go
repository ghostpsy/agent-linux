//go:build linux

package core

import (
	"encoding/json"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestMergeProcessTop_EmptySamplesIsEmptySliceNotNil(t *testing.T) {
	out := mergeProcessTop(nil)
	if out == nil {
		t.Fatal("mergeProcessTop(nil) must not return nil (JSON would be null; ingest schema requires an array)")
	}
	if len(out) != 0 {
		t.Fatalf("len=%d", len(out))
	}
}

func TestHostProcessJSONTopIsAlwaysArrayWhenPresent(t *testing.T) {
	hp := &payload.HostProcess{Top: mergeProcessTop(nil), Signals: &payload.ProcessSignals{}}
	b, err := json.Marshal(hp)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	topRaw, ok := raw["top"]
	if !ok {
		t.Fatal("missing top")
	}
	if string(topRaw) == "null" {
		t.Fatal("top must not serialize as null")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(topRaw, &arr); err != nil {
		t.Fatalf("top not array: %s", topRaw)
	}
}
