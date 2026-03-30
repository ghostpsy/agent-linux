//go:build linux

package collect

import (
	"encoding/json"
	"testing"
)

func TestEmptyIptablesItemsMarshalsToArrayNotNull(t *testing.T) {
	// V1 uses json:"iptables.items" without omitempty; a nil []string still encodes as JSON null.
	// CollectIptables must return a non-nil empty slice when save succeeds but yields no lines.
	var nilItems []string
	b, _ := json.Marshal(map[string]any{"iptables": map[string]any{"items": nilItems}})
	if string(b) != `{"iptables":{"items":null}}` {
		t.Fatalf("unexpected: %s", b)
	}
	empty := []string{}
	b2, _ := json.Marshal(map[string]any{"iptables": map[string]any{"items": empty}})
	if string(b2) != `{"iptables":{"items":[]}}` {
		t.Fatalf("empty slice must be []: %s", b2)
	}
}
