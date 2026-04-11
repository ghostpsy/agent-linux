//go:build linux

// Package security implements §9 security frameworks and malware-defense inventory (Lynis-aligned).
package security

import (
	"context"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// Collect builds security_frameworks_and_malware_defense; mac is the §1 SELinux/AppArmor summary (may be nil).
func Collect(ctx context.Context, mac *payload.SelinuxApparmorBlock) payload.SecurityFrameworksAndMalwareDefenseComponent {
	if ctx == nil {
		ctx = context.Background()
	}
	out := payload.SecurityFrameworksAndMalwareDefenseComponent{}
	if ctx.Err() != nil {
		return out
	}
	out.MacDeepPosture = collectMacDeep(ctx, mac)
	out.MalwareScannersPosture = collectMalwareScanners(ctx)
	out.Fail2banPosture = collectFail2ban(ctx)
	return out
}
