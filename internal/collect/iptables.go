//go:build linux

package collect

import (
	"log/slog"
	"os/exec"
	"strings"
)

const maxIptablesLines = 2048
const maxIptablesLineLen = 1024

// CollectIptables returns iptables-save output as non-empty lines. The second value is a non-empty
// message when the snapshot could not be collected (ingest should surface it as `iptables.error`).
func CollectIptables() ([]string, string) {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		slog.Warn("iptables-save failed", "error", err)
		return []string{}, collectionNote("iptables-save could not be run.")
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > maxIptablesLineLen {
			line = line[:maxIptablesLineLen]
		}
		lines = append(lines, line)
		if len(lines) >= maxIptablesLines {
			break
		}
	}
	if lines == nil {
		return []string{}, ""
	}
	return lines, ""
}
