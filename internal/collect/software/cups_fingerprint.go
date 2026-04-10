//go:build linux

package software

import (
	"context"
	"regexp"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

var (
	reCupsListen = regexp.MustCompile(`(?i)^\s*Listen\s+(\S+)`)
	reCupsWebIf  = regexp.MustCompile(`(?i)^\s*WebInterface\s+(\S+)`)
)

const maxCupsSampleLines = 8

// CollectCupsExposureFingerprint reads CUPS unit state and bounded cupsd config.
func CollectCupsExposureFingerprint(ctx context.Context) *payload.CupsExposureFingerprint {
	out := &payload.CupsExposureFingerprint{}
	out.UnitActiveState = systemdUnitActiveState([]string{"cups.service", "cups.socket"})
	paths := []string{"/etc/cups/cupsd.conf", "/etc/cups/cups-files.conf", "/usr/local/etc/cups/cupsd.conf"}
	for _, p := range paths {
		b, err := shared.ReadFileBounded(p, shared.DefaultConfigFileReadLimit)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if reCupsListen.MatchString(t) && len(out.ListenLinesSample) < maxCupsSampleLines {
				out.ListenLinesSample = append(out.ListenLinesSample, shared.TruncateRunes(t, 256))
			}
			if reCupsWebIf.MatchString(t) && len(out.WebInterfaceLinesSample) < 4 {
				out.WebInterfaceLinesSample = append(out.WebInterfaceLinesSample, shared.TruncateRunes(t, 256))
			}
		}
	}
	return out
}
