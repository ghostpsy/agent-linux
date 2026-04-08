//go:build linux

package network

import (
	"bufio"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxTcpWrapperSampleLines = 16

// CollectTcpWrappersFingerprint summarizes hosts.allow and hosts.deny (bounded lines).
func CollectTcpWrappersFingerprint() *payload.TcpWrappersFingerprint {
	out := &payload.TcpWrappersFingerprint{}
	allowPath := "/etc/hosts.allow"
	denyPath := "/etc/hosts.deny"
	if st, err := os.Stat(allowPath); err == nil && !st.IsDir() {
		out.HostsAllowPresent = true
		n, sample := readTcpWrapperFile(allowPath)
		out.HostsAllowLineCount = n
		out.HostsAllowSampleLines = sample
	}
	if st, err := os.Stat(denyPath); err == nil && !st.IsDir() {
		out.HostsDenyPresent = true
		n, sample := readTcpWrapperFile(denyPath)
		out.HostsDenyLineCount = n
		out.HostsDenySampleLines = sample
	}
	return out
}

func readTcpWrapperFile(path string) (count int, sample []string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if len(sample) < maxTcpWrapperSampleLines {
			sample = append(sample, shared.TruncateRunes(line, 256))
		}
	}
	return count, sample
}
