//go:build linux

package core

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	selinuxFsRoot      = "/sys/fs/selinux"
	selinuxEnforcePath = "/sys/fs/selinux/enforce"
	apparmorSummaryMax = 4096
)

// CollectSelinuxApparmor reports SELinux mode and a short AppArmor summary when available.
func CollectSelinuxApparmor() *payload.SelinuxApparmorBlock {
	out := &payload.SelinuxApparmorBlock{}
	if _, err := os.Stat(selinuxFsRoot); err != nil {
		out.SelinuxMode = ""
	} else if b, err := os.ReadFile(selinuxEnforcePath); err == nil {
		s := strings.TrimSpace(string(b))
		switch s {
		case "1":
			out.SelinuxMode = "enforcing"
		case "0":
			out.SelinuxMode = "permissive"
		default:
			out.SelinuxMode = "unknown"
		}
	} else {
		out.SelinuxMode = selinuxModeFromGetenforce()
	}
	out.ApparmorSummary = apparmorShortStatus()
	return out
}

func selinuxModeFromGetenforce() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "getenforce").Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(strings.ToLower(string(b)))
	switch s {
	case "enforcing":
		return "enforcing"
	case "permissive":
		return "permissive"
	case "disabled":
		return "disabled"
	default:
		return "unknown"
	}
}

func apparmorShortStatus() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "aa-status", "--short")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err == nil {
		return shared.TruncateRunes(strings.TrimSpace(buf.String()), apparmorSummaryMax)
	}
	cancel()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	cmd2 := exec.CommandContext(ctx2, "aa-status")
	var buf2 bytes.Buffer
	cmd2.Stdout = &buf2
	if err2 := cmd2.Run(); err2 != nil {
		return ""
	}
	return shared.TruncateRunes(strings.TrimSpace(buf2.String()), apparmorSummaryMax)
}
