//go:build linux

package identity

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const shadowPath = "/etc/shadow"

// CollectShadowAccountSummary derives non-secret counts from /etc/shadow (no hash material).
func CollectShadowAccountSummary(ctx context.Context) *payload.ShadowAccountSummary {
	return shadowSummary(ctx)
}

// collectShadowFrom reads one shadow-format file. Counts stay nil until the
// file has actually been read, so an unreadable file reports nothing rather
// than reporting zero — those are different answers.
func collectShadowFrom(path string) *payload.ShadowAccountSummary {
	out := &payload.ShadowAccountSummary{}
	f, err := os.Open(path)
	if err != nil {
		out.Error = "shadow file not readable"
		return out
	}
	defer func() { _ = f.Close() }()
	out.ShadowReadable = true

	var locked, noLogin, expired int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		pass := parts[1]
		switch {
		case pass == "":
			noLogin++
		case pass == "*" || strings.HasPrefix(pass, "!"):
			locked++
		default:
			if shadowPasswordExpiredHint(parts) {
				expired++
			}
		}
	}
	if err := sc.Err(); err != nil {
		out.Error = "shadow file read incomplete"
	}

	out.AccountsLockedCount = &locked
	out.AccountsNoLoginPasswordCount = &noLogin
	out.AccountsPasswordExpiredHintCount = &expired
	out.AccountsNeverLoggedInHintCount = lastlogNeverCount()
	return out
}

func shadowPasswordExpiredHint(parts []string) bool {
	if len(parts) < 5 {
		return false
	}
	last := strings.TrimSpace(parts[2])
	maxDays := strings.TrimSpace(parts[4])
	if last == "" || last == "0" || maxDays == "" || maxDays == "99999" || maxDays == "-1" {
		return false
	}
	lastN, err1 := strconv.Atoi(last)
	maxN, err2 := strconv.Atoi(maxDays)
	if err1 != nil || err2 != nil || maxN <= 0 {
		return false
	}
	epochDays := int(time.Now().UTC().Unix() / 86400)
	return lastN+maxN < epochDays
}

// lastlogNeverCount returns nil when lastlog could not be run: zero would claim
// every account has logged in, which is not what we learned.
func lastlogNeverCount() *int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lastlog")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "Never logged in") {
			n++
		}
	}
	return &n
}
