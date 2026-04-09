//go:build linux

package logging

import (
	"fmt"
	"os"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

var atSpoolCandidates = []string{
	"/var/spool/cron/atjobs",
	"/var/spool/at",
	"/var/spool/at/spool",
}

func collectAtBatchPosture() *payload.AtBatchPosture {
	out := &payload.AtBatchPosture{}
	out.AtdUnitActive = systemdUnitActiveBool([]string{"atd.service", "atd"})
	fillFileMeta("/etc/at.allow", &out.AtAllowPresent, &out.AtAllowModeOctal)
	fillFileMeta("/etc/at.deny", &out.AtDenyPresent, &out.AtDenyModeOctal)
	for _, p := range atSpoolCandidates {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out.SpoolPathUsed = p
			out.SpoolDirModeOctal = fmt.Sprintf("0%03o", st.Mode().Perm())
			break
		}
	}
	return out
}

func fillFileMeta(path string, present *bool, modeOct *string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	*present = true
	*modeOct = fmt.Sprintf("0%03o", st.Mode().Perm())
}
