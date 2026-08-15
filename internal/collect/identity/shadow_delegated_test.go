//go:build linux

package identity

import (
	"encoding/json"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// When the agent is not root it asks its own privileged subcommand for the
// summary. Only the summary crosses the boundary — never a password hash.
func TestDelegatedShadowSummaryIsDecoded(t *testing.T) {
	locked := 25
	raw, err := json.Marshal(&payload.ShadowAccountSummary{
		ShadowReadable:      true,
		AccountsLockedCount: &locked,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	out := decodeDelegatedShadowSummary(raw)

	if !out.ShadowReadable {
		t.Error("expected shadow_readable to survive the round trip")
	}
	if out.AccountsLockedCount == nil || *out.AccountsLockedCount != 25 {
		t.Fatalf("expected 25 locked accounts, got %v", out.AccountsLockedCount)
	}
}

// A garbled reply must not look like a server with nothing locked. It is the
// same "zero is not the same as I could not look" rule as the file path.
func TestDelegatedShadowSummaryReportsAGarbledReply(t *testing.T) {
	out := decodeDelegatedShadowSummary([]byte("not json at all"))

	if out.Error == "" {
		t.Error("expected an error to be recorded for an unreadable reply")
	}
	if out.AccountsLockedCount != nil {
		t.Errorf("expected no counts from a garbled reply, got %d", *out.AccountsLockedCount)
	}
}
