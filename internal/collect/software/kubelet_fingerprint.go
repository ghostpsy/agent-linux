//go:build linux

package software

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	kubeletSystemctlTimeout = 5 * time.Second
	maxSystemctlCatBytes    = 48 * 1024
	maxKubeletConfigPaths   = 8
	maxKubeletDropInLines   = 16
)

var (
	reReadOnlyPortYAML  = regexp.MustCompile(`^\s*readOnlyPort:\s*(\d+)\s*$`)
	reProtectKernelYAML = regexp.MustCompile(`^\s*protectKernelDefaults:\s*(true|false)\s*$`)
	reReadOnlyPortFlag  = regexp.MustCompile(`--read-only-port=(\d+)`)
	reProtectKernelFlag = regexp.MustCompile(`--protect-kernel-defaults=(true|false)`)
	reAnonymousAuthFlag = regexp.MustCompile(`--anonymous-auth=(true|false)`)
)

type kubeletHints struct {
	ReadOnlyPort          *int
	ProtectKernelDefaults *bool
	AnonymousAuthEnabled  *bool
}

func collectKubeletFingerprint() *payload.KubeletNodeFingerprint {
	out := &payload.KubeletNodeFingerprint{}
	if p, err := exec.LookPath("kubelet"); err == nil && p != "" {
		out.KubeletBinaryPath = p
	}
	var merged kubeletHints
	for _, path := range kubeletConfigPathCandidates() {
		if !fileExists(path) {
			continue
		}
		if len(out.ConfigSourcePaths) >= maxKubeletConfigPaths {
			break
		}
		out.ConfigSourcePaths = append(out.ConfigSourcePaths, path)
		b, err := shared.ReadFileBounded(path, shared.DefaultConfigFileReadLimit)
		if err != nil {
			slog.Debug("kubelet config read failed", "path", path, "error", err)
			continue
		}
		h := scanKubeletConfigYAML(string(b))
		merged.overlay(&h)
	}
	applyKubeletHints(out, &merged)
	dropIn := extractKubeletSystemdHints()
	if len(dropIn) > 0 {
		out.DropInExecSampleLines = dropIn
		overlayKubeletExecFlags(out, strings.Join(dropIn, "\n"))
	}
	if out.KubeletBinaryPath == "" && len(out.ConfigSourcePaths) == 0 && len(out.DropInExecSampleLines) == 0 {
		return nil
	}
	return out
}

func kubeletConfigPathCandidates() []string {
	return []string{
		"/var/lib/kubelet/config.yaml",
		"/etc/kubernetes/kubelet/kubelet-config.yaml",
		"/etc/kubernetes/kubelet/config.yaml",
	}
}

func (a *kubeletHints) overlay(b *kubeletHints) {
	if b == nil {
		return
	}
	if b.ReadOnlyPort != nil {
		a.ReadOnlyPort = b.ReadOnlyPort
	}
	if b.ProtectKernelDefaults != nil {
		a.ProtectKernelDefaults = b.ProtectKernelDefaults
	}
	if b.AnonymousAuthEnabled != nil {
		a.AnonymousAuthEnabled = b.AnonymousAuthEnabled
	}
}

func applyKubeletHints(out *payload.KubeletNodeFingerprint, h *kubeletHints) {
	if h == nil {
		return
	}
	out.ReadOnlyPort = h.ReadOnlyPort
	out.ProtectKernelDefaults = h.ProtectKernelDefaults
	out.AnonymousAuthEnabled = h.AnonymousAuthEnabled
}

func scanKubeletConfigYAML(body string) kubeletHints {
	var h kubeletHints
	lines := strings.Split(body, "\n")
	inAuth := false
	inAnon := false
	authIndent := 0
	for _, raw := range lines {
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = raw[:idx]
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		indent := leadingSpaceWidth(raw)
		if inAuth && indent <= authIndent && !strings.HasPrefix(strings.TrimSpace(raw), "authentication:") {
			inAuth = false
			inAnon = false
		}
		if m := reReadOnlyPortYAML.FindStringSubmatch(line); len(m) == 2 {
			if v, err := strconv.Atoi(m[1]); err == nil {
				h.ReadOnlyPort = &v
			}
			continue
		}
		if m := reProtectKernelYAML.FindStringSubmatch(line); len(m) == 2 {
			v := m[1] == "true"
			h.ProtectKernelDefaults = &v
			continue
		}
		trim := strings.TrimSpace(raw)
		if strings.HasPrefix(trim, "authentication:") {
			inAuth = true
			inAnon = false
			authIndent = indent
			continue
		}
		if inAuth && strings.HasPrefix(trim, "anonymous:") {
			inAnon = true
			continue
		}
		if inAnon && strings.HasPrefix(trim, "enabled:") {
			val := strings.TrimSpace(strings.TrimPrefix(trim, "enabled:"))
			if val == "true" {
				t := true
				h.AnonymousAuthEnabled = &t
			}
			if val == "false" {
				f := false
				h.AnonymousAuthEnabled = &f
			}
			inAnon = false
		}
	}
	return h
}

func leadingSpaceWidth(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

func extractKubeletSystemdHints() []string {
	ctx, cancel := context.WithTimeout(context.Background(), kubeletSystemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "cat", "kubelet.service")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil
	}
	full := buf.String()
	if len(full) > maxSystemctlCatBytes {
		full = full[:maxSystemctlCatBytes]
	}
	var out []string
	for _, line := range strings.Split(full, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		if !strings.Contains(line, "kubelet") {
			continue
		}
		if strings.Contains(line, "--read-only-port") || strings.Contains(line, "--protect-kernel-defaults") || strings.Contains(line, "--anonymous-auth") || strings.Contains(line, "--config=") {
			out = append(out, shared.TruncateRunes(line, 512))
			if len(out) >= maxKubeletDropInLines {
				break
			}
		}
	}
	return out
}

func overlayKubeletExecFlags(out *payload.KubeletNodeFingerprint, blob string) {
	if m := reReadOnlyPortFlag.FindStringSubmatch(blob); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			out.ReadOnlyPort = &v
		}
	}
	if m := reProtectKernelFlag.FindStringSubmatch(blob); len(m) == 2 {
		v := m[1] == "true"
		out.ProtectKernelDefaults = &v
	}
	if m := reAnonymousAuthFlag.FindStringSubmatch(blob); len(m) == 2 {
		v := m[1] == "true"
		out.AnonymousAuthEnabled = &v
	}
}
