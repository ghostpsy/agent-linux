//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/state"
	"github.com/ghostpsy/agent-linux/internal/version"
)

// envSkipUpdateNotice silences the post-scan upgrade reminder. Useful for
// CI / smoke-test cron entries that never want noise on stdout.
const envSkipUpdateNotice = "GHOSTPSY_SKIP_UPDATE_NOTICE"

// envAutoUpdate enables hands-off install of new releases (same effect as
// passing ``--auto-update`` on the scan command).
const envAutoUpdate = "GHOSTPSY_AUTO_UPDATE"

// updateReminderInterval is how long we stay quiet about the same target
// version before reminding again.
const updateReminderInterval = 7 * 24 * time.Hour

// maybePromptUpdate is called at the end of a successful scan. When a newer
// release exists it either auto-installs (opt-in) or prints a one-shot
// reminder no more often than once per ``updateReminderInterval`` per target
// version. Failures are silent — the user just ran a successful scan and
// should not be punished by transient network issues.
func maybePromptUpdate(ctx context.Context, apiURL string, st *state.AgentState, autoUpdate bool) {
	if version.Version == "dev" {
		return
	}
	if strings.TrimSpace(os.Getenv(envSkipUpdateNotice)) != "" && !autoUpdate {
		return
	}
	info, err := fetchUpdateCheck(ctx, apiURL, version.DisplayGOARCH())
	if err != nil || info.LatestVersion == "" {
		return
	}
	if !versionLess(version.Version, info.LatestVersion) {
		return
	}
	if autoUpdate {
		if err := installUpdate(ctx, info); err != nil {
			printErrorLine(fmt.Sprintf("auto-update: %v", err))
			return
		}
		printSuccessLine(fmt.Sprintf(
			"Auto-updated to version %s. The next scan will run with the new binary.",
			info.LatestVersion,
		))
		return
	}
	if !shouldRemindAboutVersion(st, info.LatestVersion, time.Now()) {
		return
	}
	printNoticeLine("")
	printNoticeLine(fmt.Sprintf(
		"A newer Ghostpsy agent is available: %s (you are on %s).",
		info.LatestVersion, version.Version,
	))
	printNoticeLine("Run `sudo ghostpsy update` to install. This reminder repeats every 7 days.")
	st.LastUpdateNotifiedVersion = info.LatestVersion
	st.LastUpdateNotifiedAt = time.Now().Unix()
	_ = state.Save(st) // best-effort: a scan that succeeded should not fail because of a reminder.
}

// shouldRemindAboutVersion is true when we have either never told the user
// about ``target`` or the previous reminder is older than the cadence. Pure
// helper so the policy is unit-testable without HTTP/state IO.
func shouldRemindAboutVersion(st *state.AgentState, target string, now time.Time) bool {
	if st == nil || target == "" {
		return target != ""
	}
	if st.LastUpdateNotifiedVersion != target {
		return true
	}
	if st.LastUpdateNotifiedAt <= 0 {
		return true
	}
	last := time.Unix(st.LastUpdateNotifiedAt, 0)
	return now.Sub(last) >= updateReminderInterval
}
