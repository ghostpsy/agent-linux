//go:build linux

package software

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxRuntimeItems = 16

type runtimeProbe struct {
	kind string
	bin  string
}

var runtimeProbes = []runtimeProbe{
	{kind: "python", bin: "python3"},
	{kind: "python", bin: "python"},
	{kind: "node", bin: "node"},
	{kind: "node", bin: "nodejs"},
	{kind: "java", bin: "java"},
	{kind: "php", bin: "php"},
	{kind: "ruby", bin: "ruby"},
	{kind: "go", bin: "go"},
}

// CollectHostRuntimes probes common interpreters on PATH (capped, M1).
func CollectHostRuntimes(ctx context.Context) *payload.HostRuntimes {
	out := &payload.HostRuntimes{Items: []payload.RuntimeEntry{}}
	seenKind := make(map[string]struct{})
	for _, probe := range runtimeProbes {
		if _, dup := seenKind[probe.kind]; dup {
			continue
		}
		entry, ok := probeRuntime(probe.kind, probe.bin)
		if !ok {
			continue
		}
		seenKind[probe.kind] = struct{}{}
		out.Items = append(out.Items, entry)
		if len(out.Items) >= maxRuntimeItems {
			break
		}
	}
	out.Docker = collectDockerHostFingerprint()
	out.Kubelet = collectKubeletFingerprint()
	return out
}

func probeRuntime(kind, bin string) (payload.RuntimeEntry, bool) {
	path, err := exec.LookPath(bin)
	if err != nil || path == "" {
		return payload.RuntimeEntry{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	version := runtimeVersion(ctx, bin, kind)
	version = strings.TrimSpace(version)
	if version == "" {
		version = "unknown"
	}
	return payload.RuntimeEntry{
		Kind:       kind,
		Version:    shared.TruncateRunes(version, 256),
		BinaryPath: path,
		ManagedBy:  classifyManagedBy(path),
	}, true
}

func runtimeVersion(ctx context.Context, bin, kind string) string {
	switch kind {
	case "java":
		cmd := exec.CommandContext(ctx, bin, "-version")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run()
		line := firstLine(stderr.String())
		return strings.TrimSpace(line)
	case "go":
		cmd := exec.CommandContext(ctx, bin, "version")
		b, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	default:
		cmd := exec.CommandContext(ctx, bin, "--version")
		b, err := cmd.CombinedOutput()
		if err != nil {
			cmd2 := exec.CommandContext(ctx, bin, "-version")
			b2, err2 := cmd2.CombinedOutput()
			if err2 != nil {
				return ""
			}
			return strings.TrimSpace(string(b2))
		}
		return strings.TrimSpace(string(b))
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func classifyManagedBy(binaryPath string) string {
	if strings.Contains(binaryPath, "/pyenv/") || strings.Contains(binaryPath, ".pyenv/") {
		return "pyenv"
	}
	if strings.HasPrefix(binaryPath, "/usr/local/bin/") || strings.HasPrefix(binaryPath, "/usr/local/sbin/") {
		return "manual"
	}
	if strings.HasPrefix(binaryPath, "/usr/") || strings.HasPrefix(binaryPath, "/opt/") {
		return "package"
	}
	if strings.HasPrefix(binaryPath, "/bin/") || strings.HasPrefix(binaryPath, "/sbin/") {
		return "package"
	}
	return "unknown"
}
