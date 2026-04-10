//go:build linux

package filesystem

import (
	"context"
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxModprobeLines = 16

// CollectUsbStoragePosture reports usb_storage load state and modprobe blacklist hints.
func CollectUsbStoragePosture(ctx context.Context) *payload.UsbStoragePosture {
	out := &payload.UsbStoragePosture{}
	out.UsbStorageLoaded = moduleLoaded("usb_storage")
	out.BlacklistUsbStorageLinePresent, out.ModprobeFragmentLinesSample = scanModprobeUsbBlacklist()
	return out
}

func moduleLoaded(name string) bool {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	prefix := name + " "
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func scanModprobeUsbBlacklist() (blacklistLine bool, sample []string) {
	matches, err := filepath.Glob("/etc/modprobe.d/*.conf")
	if err != nil {
		return false, nil
	}
	for _, path := range matches {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			low := strings.ToLower(line)
			if strings.Contains(low, "usb-storage") || strings.Contains(low, "usb_storage") {
				if strings.HasPrefix(low, "blacklist") {
					blacklistLine = true
				}
				if len(sample) < maxModprobeLines {
					sample = append(sample, shared.TruncateRunes(line, 256))
				}
			}
		}
		_ = f.Close()
	}
	return blacklistLine, sample
}
