//go:build linux

package software

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	dockerInfoTimeout  = 6 * time.Second
	dockerDaemonJSON   = "/etc/docker/daemon.json"
	dockerSockDefault  = "/var/run/docker.sock"
	dockerSockRun      = "/run/docker.sock"
	maxDockerInfoBytes = 512 * 1024
)

type dockerDaemonJSONKeys struct {
	LiveRestore   *bool  `json:"live-restore"`
	Icc           *bool  `json:"icc"`
	UserlandProxy *bool  `json:"userland-proxy"`
	Tls           *bool  `json:"tls"`
	TlsVerify     *bool  `json:"tlsverify"`
	Tlscacert     string `json:"tlscacert"`
	Tlscert       string `json:"tlscert"`
	Tlskey        string `json:"tlskey"`
}

type dockerInfoJSON struct {
	Containers      int      `json:"Containers"`
	SecurityOptions []string `json:"SecurityOptions"`
	Rootless        bool     `json:"Rootless"`
}

func collectDockerHostFingerprint() *payload.DockerHostFingerprint {
	dockerPath, err := exec.LookPath("docker")
	hasDockerCLI := err == nil && dockerPath != ""
	sockPath := resolveDockerSocketPath()
	hasDaemonJSON := fileExists(dockerDaemonJSON)
	if !hasDockerCLI && sockPath == "" && !hasDaemonJSON {
		return nil
	}
	out := &payload.DockerHostFingerprint{}
	if hasDockerCLI {
		out.DockerCliPath = dockerPath
	}
	if hasDaemonJSON {
		if d := readDockerDaemonJSON(dockerDaemonJSON); d != nil {
			out.DaemonJSONPath = dockerDaemonJSON
			applyDaemonJSON(out, d)
		}
	}
	if sockPath != "" {
		fillDockerSockStat(out, sockPath)
	}
	if hasDockerCLI {
		if infoErr := fillDockerInfo(out, dockerPath); infoErr != "" {
			out.Error = shared.TruncateRunes(infoErr, 512)
		}
	}
	if out.RootlessHint == "" {
		out.RootlessHint = inferRootlessFromSock(sockPath)
	}
	return out
}

func resolveDockerSocketPath() string {
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(host, "unix://") {
		u, err := url.Parse(host)
		if err != nil {
			return ""
		}
		p := u.Path
		if p != "" && fileExists(p) {
			return p
		}
	}
	for _, c := range []string{dockerSockDefault, dockerSockRun} {
		if fileExists(c) {
			return c
		}
	}
	matches, _ := filepath.Glob("/run/user/*/docker.sock")
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func readDockerDaemonJSON(path string) *dockerDaemonJSONKeys {
	b, err := os.ReadFile(path)
	if err != nil {
		slog.Debug("docker daemon.json not readable", "path", path, "error", err)
		return nil
	}
	if len(b) > maxConfigReadBytes {
		b = b[:maxConfigReadBytes]
	}
	var d dockerDaemonJSONKeys
	if err := json.Unmarshal(b, &d); err != nil {
		slog.Warn("docker daemon.json parse failed", "path", path, "error", err)
		return nil
	}
	return &d
}

func applyDaemonJSON(out *payload.DockerHostFingerprint, d *dockerDaemonJSONKeys) {
	out.LiveRestore = d.LiveRestore
	out.Icc = d.Icc
	out.UserlandProxy = d.UserlandProxy
	if d.Tls != nil {
		out.TlsInDaemonJSON = d.Tls
	} else if tlsMaterialPresent(d) {
		v := true
		out.TlsInDaemonJSON = &v
	}
	if d.TlsVerify != nil {
		out.TlsVerifyInDaemonJSON = d.TlsVerify
	}
}

func tlsMaterialPresent(d *dockerDaemonJSONKeys) bool {
	return strings.TrimSpace(d.Tlscacert) != "" || strings.TrimSpace(d.Tlscert) != "" || strings.TrimSpace(d.Tlskey) != ""
}

func fillDockerSockStat(out *payload.DockerHostFingerprint, sockPath string) {
	st, err := os.Stat(sockPath)
	if err != nil {
		slog.Debug("docker socket stat failed", "path", sockPath, "error", err)
		return
	}
	out.DockerSockPath = sockPath
	out.DockerSockModeOctal = fmt.Sprintf("%04o", st.Mode().Perm())
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid := int(sys.Uid)
	gid := int(sys.Gid)
	out.DockerSockOwnerUID = &uid
	out.DockerSockGroupGID = &gid
}

func fillDockerInfo(out *payload.DockerHostFingerprint, dockerPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), dockerInfoTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, dockerPath, "info", "--format", "{{json .}}")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(buf.String())
		if msg == "" {
			msg = "docker info failed"
		}
		return msg
	}
	raw := buf.Bytes()
	if len(raw) > maxDockerInfoBytes {
		raw = raw[:maxDockerInfoBytes]
	}
	var info dockerInfoJSON
	if err := json.Unmarshal(raw, &info); err != nil {
		return "docker info returned invalid json"
	}
	c := info.Containers
	out.ContainerCount = &c
	if info.Rootless {
		out.RootlessHint = "rootless"
		return ""
	}
	for _, opt := range info.SecurityOptions {
		if strings.Contains(strings.ToLower(opt), "rootless") {
			out.RootlessHint = "rootless"
			return ""
		}
	}
	out.RootlessHint = "rootful"
	return ""
}

func inferRootlessFromSock(sockPath string) string {
	if sockPath == "" {
		return ""
	}
	if strings.Contains(sockPath, "/run/user/") {
		return "likely_rootless"
	}
	return "unknown"
}
