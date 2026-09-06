//go:build linux

package network

import (
	"context"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxLegacyUnitSample = 16

const legacySystemctlListTimeout = 10 * time.Second

// CollectLegacyInsecureServices reports telnet, rsh, rlogin and rexec hints from
// both places a machine can switch them on: systemd units, and inetd.
//
// Asking systemd alone answered "none of these" on every machine without it —
// which is exactly the kind of machine old enough to still be running telnet.
// The inetd.conf lines were already being counted; nothing read what they said.
func CollectLegacyInsecureServices(ctx context.Context) *payload.LegacyInsecureServices {
	out := &payload.LegacyInsecureServices{}
	ctx, cancel := context.WithTimeout(ctx, legacySystemctlListTimeout)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--no-legend").Output(); err == nil {
		lower := strings.ToLower(string(b))
		out.TelnetSuspected = strings.Contains(lower, "telnet")
		out.RshSuspected = strings.Contains(lower, "rsh") || strings.Contains(lower, "rshd")
		out.RloginSuspected = strings.Contains(lower, "rlogin")
		out.RexecSuspected = strings.Contains(lower, "rexec")
		out.VsftpdSuspected = strings.Contains(lower, "vsftpd")
		out.ProftpdSuspected = strings.Contains(lower, "proftpd")
		out.SystemdUnitNamesSample = sampleLegacyUnitLines(string(b))
	}
	if st, err := os.Stat("/etc/inetd.conf"); err == nil && !st.IsDir() {
		out.InetdConfPresent = true
		out.InetdConfNonCommentLines = countInetdNonCommentLines()
		markLegacyServicesFromInetd(out)
	}
	return out
}

// inetdServiceFlags maps the service name in the first column of an inetd.conf
// line to the thing we report. The names are the ones in /etc/services, which is
// why rsh appears as "shell" and rlogin as "login".
var inetdServiceFlags = map[string]func(*payload.LegacyInsecureServices){
	"telnet": func(o *payload.LegacyInsecureServices) { o.TelnetSuspected = true },
	"shell":  func(o *payload.LegacyInsecureServices) { o.RshSuspected = true },
	"login":  func(o *payload.LegacyInsecureServices) { o.RloginSuspected = true },
	"exec":   func(o *payload.LegacyInsecureServices) { o.RexecSuspected = true },
}

// inetdServerFlags maps the program an inetd line runs to the same flags, for a
// machine that gave the service a name of its own.
var inetdServerFlags = map[string]func(*payload.LegacyInsecureServices){
	"in.telnetd": func(o *payload.LegacyInsecureServices) { o.TelnetSuspected = true },
	"in.rshd":    func(o *payload.LegacyInsecureServices) { o.RshSuspected = true },
	"in.rlogind": func(o *payload.LegacyInsecureServices) { o.RloginSuspected = true },
	"in.rexecd":  func(o *payload.LegacyInsecureServices) { o.RexecSuspected = true },
	"vsftpd":     func(o *payload.LegacyInsecureServices) { o.VsftpdSuspected = true },
	"proftpd":    func(o *payload.LegacyInsecureServices) { o.ProftpdSuspected = true },
}

// markLegacyServicesFromInetd reads what inetd is actually set to start.
//
// Commented lines are skipped, because a line behind a # is how these services
// are usually turned off, and reporting one as live would send somebody looking
// for a service that is not there.
func markLegacyServicesFromInetd(out *payload.LegacyInsecureServices) {
	b, err := shared.ReadFileBounded("/etc/inetd.conf", shared.DefaultConfigFileReadLimit)
	if err != nil {
		return
	}
	markLegacyServicesFromInetdText(out, string(b))
}

// markLegacyServicesFromInetdText is the reading on its own, so it can be tested
// without an /etc/inetd.conf on the machine running the tests.
func markLegacyServicesFromInetdText(out *payload.LegacyInsecureServices, text string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 0 {
			continue
		}
		if mark, ok := inetdServiceFlags[fields[0]]; ok {
			mark(out)
		}
		for _, f := range fields[1:] {
			if mark, ok := inetdServerFlags[path.Base(f)]; ok {
				mark(out)
			}
		}
	}
}

func sampleLegacyUnitLines(statusOut string) []string {
	var out []string
	for _, line := range strings.Split(statusOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "telnet") || strings.Contains(low, "rsh") ||
			strings.Contains(low, "rlogin") || strings.Contains(low, "rexec") ||
			strings.Contains(low, "vsftpd") || strings.Contains(low, "proftpd") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				out = append(out, shared.TruncateRunes(fields[0], 128))
			}
		}
		if len(out) >= maxLegacyUnitSample {
			break
		}
	}
	return out
}

func countInetdNonCommentLines() int {
	b, err := shared.ReadFileBounded("/etc/inetd.conf", shared.DefaultConfigFileReadLimit)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}
