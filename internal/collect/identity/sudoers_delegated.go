//go:build linux

package identity

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// sudoersAudit reads /etc/sudoers and its directory when it can, and asks its
// own privileged subcommand when it cannot. Same reason as the shadow file: a
// path is not an exact sudo command, so the agent delegates to itself.
//
// It returns the counts, never the rule bodies. A sudoers file describes who
// can become root on this machine, and there is no reason for that text to
// travel when the numbers answer the question.
func sudoersAudit(ctx context.Context) *payload.SudoersAudit {
	if os.Geteuid() == 0 {
		return collectSudoersAuditLocal()
	}

	res, err := privexec.Run(ctx, privexec.ReadSudoers)
	if err != nil {
		return &payload.SudoersAudit{Error: "sudoers could not be read"}
	}
	return decodeDelegatedSudoersAudit(res.Stdout)
}

func decodeDelegatedSudoersAudit(raw []byte) *payload.SudoersAudit {
	var out payload.SudoersAudit
	if err := json.Unmarshal(raw, &out); err != nil {
		return &payload.SudoersAudit{Error: "sudoers summary could not be read"}
	}
	return &out
}

// SudoersAuditJSON renders the audit for the privileged subcommand to print.
func SudoersAuditJSON() ([]byte, error) {
	return json.Marshal(collectSudoersAuditLocal())
}
