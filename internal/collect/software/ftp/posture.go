//go:build linux

// Package ftp collects bounded security posture for FTP servers (vsftpd, ProFTPD, Pure-FTPd).
// No credentials, no user lists, no file contents.
package ftp

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

var reVersion = regexp.MustCompile(`([\d]+\.[\d]+\.[\d]+)`)

type ftpDaemon struct {
	name         string
	binNames     []string
	commonPaths  []string
	serviceNames []string
	configPaths  []string
}

var knownDaemons = []ftpDaemon{
	{
		name:         "vsftpd",
		binNames:     []string{"vsftpd"},
		commonPaths:  []string{"/usr/sbin/vsftpd"},
		serviceNames: []string{"vsftpd.service"},
		configPaths:  []string{"/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"},
	},
	{
		name:         "proftpd",
		binNames:     []string{"proftpd"},
		commonPaths:  []string{"/usr/sbin/proftpd", "/usr/local/sbin/proftpd"},
		serviceNames: []string{"proftpd.service"},
		configPaths:  []string{"/etc/proftpd/proftpd.conf", "/etc/proftpd.conf"},
	},
	{
		name:         "pure-ftpd",
		binNames:     []string{"pure-ftpd"},
		commonPaths:  []string{"/usr/sbin/pure-ftpd", "/usr/local/sbin/pure-ftpd"},
		serviceNames: []string{"pure-ftpd.service"},
		configPaths:  []string{"/etc/pure-ftpd/pure-ftpd.conf", "/etc/pure-ftpd.conf"},
	},
}

// CollectFtpPosture detects and collects FTP server posture.
// Returns nil when no FTP daemon is found.
func CollectFtpPosture(ctx context.Context, services []payload.ServiceEntry) *payload.FtpPosture {
	for _, d := range knownDaemons {
		bin := resolveBinary(d)
		if bin == "" {
			continue
		}
		out := &payload.FtpPosture{
			Detected: true,
			BinPath:  bin,
			Daemon:   d.name,
		}
		out.Version = extractVersion(ctx, bin, d.name)
		out.ServiceState = serviceState(ctx, services, d.serviceNames)
		parseConfig(d, out)
		if out.CollectorWarnings == nil {
			out.CollectorWarnings = []string{}
		}
		return out
	}
	return nil
}

func resolveBinary(d ftpDaemon) string {
	for _, name := range d.binNames {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range d.commonPaths {
		if shared.FileExistsRegular(p) {
			return p
		}
	}
	return ""
}

func extractVersion(ctx context.Context, bin, daemon string) *string {
	var cmd *exec.Cmd
	switch daemon {
	case "vsftpd":
		cmd = exec.CommandContext(ctx, bin, "-v")
	case "proftpd":
		cmd = exec.CommandContext(ctx, bin, "-v")
	case "pure-ftpd":
		cmd = exec.CommandContext(ctx, bin, "--help")
	default:
		return nil
	}
	out, err := cmd.CombinedOutput()
	if err != nil && daemon != "pure-ftpd" {
		// pure-ftpd --help exits non-zero but still prints version
		return nil
	}
	m := reVersion.FindStringSubmatch(string(out))
	if len(m) >= 2 {
		return shared.StringPtr(m[1])
	}
	return nil
}

func serviceState(ctx context.Context, services []payload.ServiceEntry, names []string) *string {
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	for _, e := range services {
		if _, ok := want[e.Name]; !ok {
			continue
		}
		st := systemdutil.MapActiveStateForPosture(e.ActiveState)
		if st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	for _, n := range names {
		if st := systemdutil.SystemctlIsActiveState(ctx, n); st == "running" || st == "stopped" {
			return shared.StringPtr(st)
		}
	}
	return nil
}

func parseConfig(d ftpDaemon, out *payload.FtpPosture) {
	switch d.name {
	case "vsftpd":
		parseVsftpd(d.configPaths, out)
	case "proftpd":
		parseProftpd(d.configPaths, out)
	case "pure-ftpd":
		parsePureFtpd(d.configPaths, out)
	}
}

func parseVsftpd(paths []string, out *payload.FtpPosture) {
	kv := readKeyValueConfig(paths)
	if kv == nil {
		return
	}
	out.AnonymousEnabled = boolFromYesNo(kv["anonymous_enable"])
	out.TlsEnabled = boolFromYesNo(kv["ssl_enable"])
	out.ChrootEnabled = boolFromYesNo(kv["chroot_local_user"])
	if v, ok := kv["listen_address"]; ok {
		out.ListenAddress = shared.StringPtr(v)
	}
	if v, ok := kv["listen_port"]; ok {
		out.ListenPort = shared.StringPtr(v)
	}
	if v, ok := kv["pasv_min_port"]; ok {
		out.PasvMinPort = shared.StringPtr(v)
	}
	if v, ok := kv["pasv_max_port"]; ok {
		out.PasvMaxPort = shared.StringPtr(v)
	}
}

func parseProftpd(paths []string, out *payload.FtpPosture) {
	kv := readApacheStyleConfig(paths)
	if kv == nil {
		return
	}
	if v, ok := kv["defaultroot"]; ok {
		out.ChrootEnabled = shared.BoolPtr(v != "")
	}
	if _, ok := kv["tlsengine"]; ok {
		out.TlsEnabled = shared.BoolPtr(true)
	}
	// Anonymous block detection
	if _, ok := kv["<anonymous"]; ok {
		out.AnonymousEnabled = shared.BoolPtr(true)
	}
	if v, ok := kv["port"]; ok {
		out.ListenPort = shared.StringPtr(v)
	}
	if v, ok := kv["passiveports"]; ok {
		parts := strings.Fields(v)
		if len(parts) >= 2 {
			out.PasvMinPort = shared.StringPtr(parts[0])
			out.PasvMaxPort = shared.StringPtr(parts[1])
		}
	}
}

func parsePureFtpd(paths []string, out *payload.FtpPosture) {
	kv := readKeyValueConfig(paths)
	if kv == nil {
		return
	}
	if v, ok := kv["noanonymous"]; ok {
		out.AnonymousEnabled = shared.BoolPtr(v != "yes")
	}
	if v, ok := kv["anonymousonly"]; ok && v == "yes" {
		out.AnonymousEnabled = shared.BoolPtr(true)
	}
	if v, ok := kv["tls"]; ok {
		out.TlsEnabled = shared.BoolPtr(v != "0")
	}
	if v, ok := kv["chrooteveryone"]; ok {
		out.ChrootEnabled = shared.BoolPtr(v == "yes")
	}
	if v, ok := kv["bind"]; ok {
		out.ListenAddress = shared.StringPtr(v)
	}
	if v, ok := kv["passiveportrange"]; ok {
		parts := strings.Fields(v)
		if len(parts) >= 2 {
			out.PasvMinPort = shared.StringPtr(parts[0])
			out.PasvMaxPort = shared.StringPtr(parts[1])
		}
	}
}

// readKeyValueConfig reads the first existing config file as KEY=VALUE pairs.
func readKeyValueConfig(paths []string) map[string]string {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer func() { _ = f.Close() }()
		kv := make(map[string]string)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				kv[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
			}
		}
		return kv
	}
	return nil
}

// readApacheStyleConfig reads ProFTPD-style config (Directive Value).
func readApacheStyleConfig(paths []string) map[string]string {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer func() { _ = f.Close() }()
		kv := make(map[string]string)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "<anonymous") {
				kv["<anonymous"] = "true"
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kv[strings.ToLower(parts[0])] = strings.Join(parts[1:], " ")
			} else if len(parts) == 1 {
				kv[strings.ToLower(parts[0])] = ""
			}
		}
		return kv
	}
	return nil
}

func boolFromYesNo(v string) *bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "yes" {
		return shared.BoolPtr(true)
	}
	if s == "no" {
		return shared.BoolPtr(false)
	}
	return nil
}
