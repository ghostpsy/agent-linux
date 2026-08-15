//go:build linux

package identity

import (
	"encoding/json"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestDelegatedSudoersAuditIsDecoded(t *testing.T) {
	raw, err := json.Marshal(&payload.SudoersAudit{
		NopasswdMentionCount: 7,
		FilesScanned:         []string{"/etc/sudoers"},
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	out := decodeDelegatedSudoersAudit(raw)

	if out.NopasswdMentionCount != 7 {
		t.Errorf("expected 7 NOPASSWD mentions, got %d", out.NopasswdMentionCount)
	}
	if len(out.FilesScanned) != 1 {
		t.Errorf("expected the scanned file list to survive, got %v", out.FilesScanned)
	}
}

// A garbled reply must not look like a host with a clean sudoers file. Zero
// risky lines and "I could not look" are different answers.
func TestDelegatedSudoersAuditReportsAGarbledReply(t *testing.T) {
	out := decodeDelegatedSudoersAudit([]byte("{{{"))

	if out.Error == "" {
		t.Error("expected an error to be recorded for an unreadable reply")
	}
	if len(out.FilesScanned) != 0 {
		t.Errorf("expected no files reported as scanned, got %v", out.FilesScanned)
	}
}
