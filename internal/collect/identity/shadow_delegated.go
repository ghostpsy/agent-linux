//go:build linux

package identity

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// shadowSummary reads /etc/shadow when it can, and asks its own privileged
// subcommand when it cannot.
//
// A file path cannot be written as an exact sudo command, so /etc/shadow is one
// of the few places the agent delegates to itself. The subcommand returns the
// summary only: a password hash never crosses the boundary, which granting
// `cat /etc/shadow` would not give us.
func shadowSummary(ctx context.Context) *payload.ShadowAccountSummary {
	if os.Geteuid() == 0 {
		return collectShadowFrom(shadowPath)
	}

	res, err := privexec.Run(ctx, privexec.ReadShadow)
	if err != nil {
		return &payload.ShadowAccountSummary{Error: "shadow file not readable"}
	}
	return decodeDelegatedShadowSummary(res.Stdout)
}

// decodeDelegatedShadowSummary reads what the privileged subcommand printed. A
// garbled reply records an error rather than an empty summary, because zero
// locked accounts and "I could not look" are different answers.
func decodeDelegatedShadowSummary(raw []byte) *payload.ShadowAccountSummary {
	var out payload.ShadowAccountSummary
	if err := json.Unmarshal(raw, &out); err != nil {
		return &payload.ShadowAccountSummary{Error: "shadow summary could not be read"}
	}
	return &out
}

// ShadowSummaryJSON renders the summary for the privileged subcommand to print.
func ShadowSummaryJSON() ([]byte, error) {
	return json.Marshal(collectShadowFrom(shadowPath))
}
