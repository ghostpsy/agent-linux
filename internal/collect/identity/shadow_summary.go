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
func CollectShadowAccountSummary() *payload.ShadowAccountSummary {
	out := &payload.ShadowAccountSummary{}
	f, err := os.Open(shadowPath)
	if err != nil {
		out.Error = "shadow file not readable"
		return out
	}
	defer func() { _ = f.Close() }()
	out.ShadowReadable = true
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
			out.AccountsNoLoginPasswordCount++
		case pass == "*" || strings.HasPrefix(pass, "!"):
			out.AccountsLockedCount++
		default:
			exp := shadowPasswordExpiredHint(parts)
			if exp {
				out.AccountsPasswordExpiredHintCount++
			}
		}
	}
	if err := sc.Err(); err != nil {
		out.Error = "shadow file read incomplete"
	}
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

func lastlogNeverCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lastlog")
	b, err := cmd.Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "Never logged in") {
			n++
		}
	}
	return n
}
