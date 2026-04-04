package state

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

// MachineUUIDFromOS returns a UUID derived from the host D-Bus/machine ID when available.
//
// We do not use github.com/shirou/gopsutil/v4/host.HostID (see host_linux.go): that API tries
// /sys/class/dmi/id/product_uuid first, then /etc/machine-id, then /proc/sys/kernel/random/boot_id.
// For Ghostpsy we need (1) stable OS identity from /etc/machine-id (e.g. Docker audit entrypoint may seed it),
// not DMI product UUID, and (2) never boot_id, which changes every reboot and would create a new
// machine row after each boot.
// Linux writes 32 lowercase hex bytes to /etc/machine-id (or /var/lib/dbus/machine-id).
// The value is formatted as a standard UUID string for ingest (backend stores uuid.UUID).
func MachineUUIDFromOS() (string, bool) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		u, ok := parseDBusMachineIDToUUID(s)
		if ok {
			return u.String(), true
		}
	}
	return "", false
}

func parseDBusMachineIDToUUID(s string) (uuid.UUID, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "-", ""))
	if len(s) != 32 {
		return uuid.Nil, false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return uuid.Nil, false
	}
	formatted := fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
	u, err := uuid.Parse(formatted)
	if err != nil {
		return uuid.Nil, false
	}
	return u, true
}
