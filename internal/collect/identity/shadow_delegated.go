//go:build linux

package identity

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// shadowSummary reads /etc/shadow when it can, and asks two standard commands
// when it cannot.
//
// As root it reads the file. As the agent's own unprivileged user it runs
// `passwd -S -a` and `lastlog`, both through sudo, and counts what they print.
// Neither prints password material: `passwd -S -a` gives one status letter per
// account, and lastlog gives login times.
//
// It used to run `ghostpsy read-shadow` instead. That was equally safe and quite
// unreadable — the sudo rule named our binary, so nobody could tell what ran as
// root without reading our source. These two commands say it on sight.
func shadowSummary(ctx context.Context) *payload.ShadowAccountSummary {
	if os.Geteuid() == 0 {
		return collectShadowFrom(shadowPath)
	}

	res, err := privexec.Run(ctx, privexec.ShadowAccountStatus)
	if err != nil {
		return &payload.ShadowAccountSummary{Error: "account status could not be read"}
	}
	status := parsePasswdStatus(res.Stdout)

	// Every Linux machine has root. Nought understood lines means the reply was
	// not what we expected, and reporting "no locked accounts" for that would be
	// a clean bill of health invented out of a failure.
	if status.total == 0 {
		return &payload.ShadowAccountSummary{Error: "account status could not be read"}
	}

	// lastlog answers a question of its own, so it gets its own call and its own
	// failure. Losing it must not lose the counts we already have.
	neverLoggedIn := (*int)(nil)
	if lastlogRes, lastlogErr := privexec.Run(ctx, privexec.LastlogAll); lastlogErr == nil {
		neverLoggedIn = intPtr(countNeverLoggedIn(lastlogRes.Stdout))
	}

	return &payload.ShadowAccountSummary{
		ShadowReadable:                   true,
		AccountsLockedCount:              intPtr(status.locked),
		AccountsNoLoginPasswordCount:     intPtr(status.noPassword),
		AccountsPasswordExpiredHintCount: intPtr(status.expired),
		AccountsNeverLoggedInHintCount:   neverLoggedIn,
	}
}

// ShadowSummaryJSON renders the summary from the file itself. Only root can do
// this, and only the scan running as root ever calls it.
func ShadowSummaryJSON() ([]byte, error) {
	return json.Marshal(collectShadowFrom(shadowPath))
}
