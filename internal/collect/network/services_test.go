//go:build linux

package network

import (
	"encoding/json"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

// Ingest schema requires services.items to be a JSON array (never null).
func TestServicesBlockUnsupportedCollectorJSONHasItemsArray(t *testing.T) {
	b := payload.ServicesBlock{
		Items: []payload.ServiceEntry{},
		Error: shared.CollectionNote("no supported service collector detected."),
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	items, ok := decoded["items"]
	if !ok {
		t.Fatal("expected items in JSON")
	}
	if items == nil {
		t.Fatal("items must serialize as [] for ingest schema, not null")
	}
}
