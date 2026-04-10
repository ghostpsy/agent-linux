//go:build linux

package core

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const efiSysfs = "/sys/firmware/efi"

// CollectFirmwareBoot detects UEFI vs BIOS hints (no root required for sysfs).
func CollectFirmwareBoot(ctx context.Context) *payload.FirmwareBoot {
	out := &payload.FirmwareBoot{BootMode: "unknown"}
	st, err := os.Stat(efiSysfs)
	if err == nil && st.IsDir() {
		out.EfiSysfsPresent = true
		out.BootMode = "uefi"
	} else {
		out.EfiSysfsPresent = false
		out.BootMode = "bios"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "efibootmgr", "-v")
	if err := cmd.Run(); err == nil {
		out.EfibootmgrExitZero = true
		if !out.EfiSysfsPresent {
			out.BootMode = "uefi"
		}
	}
	return out
}
