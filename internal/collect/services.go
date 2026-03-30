//go:build linux

package collect

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"

	"ghostpsy/agent-linux/internal/payload"
)

const maxServices = 256

const serviceCollectTimeout = 15 * time.Second

// CollectServices lists running services: systemd (D-Bus) when pid 1 is systemd, otherwise sysvinit
// (Debian/Ubuntu-style `service --status-all` parsing).
// The second return is non-empty when service inventory could not be collected.
func CollectServices() ([]payload.ServiceEntry, string) {
	mode := detectServiceCollector()
	switch mode {
	case "systemd":
		return collectSystemdServices()
	case "chkconfig":
		return collectFromChkconfig()
	case "service":
		serviceBin, _ := exec.LookPath("service")
		return collectFromServiceStatusAll(serviceBin)
	default:
		return nil, collectionNote("no supported service collector detected.")
	}
}

// isSystemdPID1 is true when PID 1 is systemd.
// Relying on /run/systemd/system alone is too optimistic in containers.
func isSystemdPID1() bool {
	b, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "systemd"
}

func hasSystemDBusSocket() bool {
	if st, err := os.Stat("/var/run/dbus/system_bus_socket"); err == nil && !st.IsDir() {
		return true
	}
	if st, err := os.Stat("/run/dbus/system_bus_socket"); err == nil && !st.IsDir() {
		return true
	}
	return false
}

func detectServiceCollector() string {
	// Deterministic choice (no cascading fallbacks): pick one collector path from environment facts.
	if isSystemdPID1() && hasSystemDBusSocket() {
		return "systemd"
	}
	if _, err := exec.LookPath("chkconfig"); err == nil {
		return "chkconfig"
	}
	if _, err := exec.LookPath("service"); err == nil {
		return "service"
	}
	return ""
}

// collectSystemdServices lists running .service units with optional unit-file state (capped).
func collectSystemdServices() ([]payload.ServiceEntry, string) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceCollectTimeout)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		slog.Warn("systemd dbus connection failed", "error", err)
		return nil, collectionNote("systemd D-Bus connection failed.")
	}
	defer conn.Close()

	units, err := conn.ListUnitsByPatternsContext(ctx, []string{"running"}, []string{"*.service"})
	if err != nil {
		slog.Warn("systemd ListUnitsByPatterns failed", "error", err)
		return nil, collectionNote("systemd could not list running service units.")
	}
	if len(units) == 0 {
		return []payload.ServiceEntry{}, ""
	}

	fileState := loadSystemdUnitFileStates(ctx, conn)
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	var out []payload.ServiceEntry
	for _, u := range units {
		if len(out) >= maxServices {
			break
		}
		name := strings.TrimSpace(u.Name)
		if name == "" {
			continue
		}
		active := strings.TrimSpace(u.ActiveState)
		sub := strings.TrimSpace(u.SubState)
		activeState := active
		if sub != "" && sub != active {
			activeState = active + "/" + sub
		}
		se := payload.ServiceEntry{
			Name:        name,
			Manager:     "systemd",
			ActiveState: truncateRunes(activeState, 32),
		}
		if st, ok := fileState[name]; ok {
			se.UnitFileState = truncateRunes(st, 32)
			se.Enabled = unitFileEnabledPtr(st)
		}
		out = append(out, se)
	}
	if len(out) == 0 {
		return []payload.ServiceEntry{}, ""
	}
	return out, ""
}

func collectFromServiceStatusAll(serviceBin string) ([]payload.ServiceEntry, string) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceCollectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, serviceBin, "--status-all")
	cmd.Env = envLocaleC()
	combined, err := cmd.CombinedOutput()
	if err != nil && len(strings.TrimSpace(string(combined))) == 0 {
		slog.Warn("sysvinit service --status-all failed", "error", err)
		return nil, collectionNote("service --status-all did not return usable output.")
	}
	names := parseServiceStatusAll(combined)
	if len(names) == 0 {
		return []payload.ServiceEntry{}, ""
	}
	sort.Strings(names)
	var out []payload.ServiceEntry
	for _, name := range names {
		if len(out) >= maxServices {
			break
		}
		name = truncateRunes(strings.TrimSpace(name), 256)
		if name == "" {
			continue
		}
		se := payload.ServiceEntry{
			Name:        name,
			Manager:     "sysvinit",
			ActiveState: "running",
		}
		se.Enabled = sysvinitScriptEnabledPtr(name)
		out = append(out, se)
	}
	if len(out) == 0 {
		return []payload.ServiceEntry{}, ""
	}
	return out, ""
}

func collectFromChkconfig() ([]payload.ServiceEntry, string) {
	chkconfigBin, err := exec.LookPath("chkconfig")
	if err != nil {
		return nil, collectionNote("service and chkconfig commands not found; sysvinit service list unavailable.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceCollectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, chkconfigBin, "--list")
	cmd.Env = envLocaleC()
	combined, err := cmd.CombinedOutput()
	if err != nil && len(strings.TrimSpace(string(combined))) == 0 {
		slog.Warn("chkconfig --list failed", "error", err)
		return nil, collectionNote("chkconfig --list did not return usable output.")
	}
	rows := parseChkconfigList(combined)
	if len(rows) == 0 {
		return nil, collectionNote("chkconfig did not report any SysV services.")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	if len(rows) > maxServices {
		rows = rows[:maxServices]
	}
	return rows, ""
}

func parseChkconfigList(output []byte) []payload.ServiceEntry {
	sc := bufio.NewScanner(strings.NewReader(string(output)))
	var out []payload.ServiceEntry
	seen := make(map[string]struct{})
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "note:") || strings.HasPrefix(lower, "if you want") || strings.HasPrefix(lower, "to see services") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := truncateRunes(strings.TrimSpace(fields[0]), 256)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		var enabled *bool
		hasRunlevelData := false
		for _, f := range fields[1:] {
			_, state, ok := strings.Cut(f, ":")
			if !ok {
				continue
			}
			hasRunlevelData = true
			switch strings.ToLower(strings.TrimSpace(state)) {
			case "on":
				t := true
				enabled = &t
			case "off":
				if enabled == nil {
					f := false
					enabled = &f
				}
			}
		}
		if !hasRunlevelData {
			continue
		}
		entry := payload.ServiceEntry{
			Name:        name,
			Manager:     "sysvinit",
			ActiveState: "unknown",
			Enabled:     enabled,
		}
		out = append(out, entry)
		seen[name] = struct{}{}
	}
	return out
}

// parseServiceStatusAll returns init script names that are running ([ + ]).
func parseServiceStatusAll(output []byte) []string {
	var names []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimRight(line, "\r")
		m := serviceStatusAllLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[1] == "+" {
			names = append(names, m[2])
		}
	}
	return names
}

var serviceStatusAllLine = regexp.MustCompile(`^\s*\[\s*([+\-?])\s*\]\s+(\S+)`)

// sysvinitScriptEnabledPtr reports whether an S??name symlink exists under /etc/rc*.d (best-effort).
func sysvinitScriptEnabledPtr(script string) *bool {
	if script == "" {
		return nil
	}
	for _, rd := range []string{"S", "0", "1", "2", "3", "4", "5", "6"} {
		dir := filepath.Join("/etc", "rc"+rd+".d")
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "S*"+script))
		if len(matches) > 0 {
			t := true
			return &t
		}
	}
	return nil
}

func loadSystemdUnitFileStates(ctx context.Context, conn *dbus.Conn) map[string]string {
	files, err := conn.ListUnitFilesByPatternsContext(ctx, nil, []string{"*.service"})
	if err != nil {
		slog.Warn("systemd ListUnitFilesByPatterns failed", "error", err)
		return nil
	}
	if len(files) == 0 {
		return nil
	}
	m := make(map[string]string, len(files))
	for _, f := range files {
		base := strings.TrimSpace(path.Base(f.Path))
		if base == "" || base == "." {
			continue
		}
		st := strings.TrimSpace(f.Type)
		if st != "" {
			m[base] = st
		}
	}
	return m
}

func unitFileEnabledPtr(state string) *bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "enabled":
		t := true
		return &t
	case "disabled":
		f := false
		return &f
	default:
		return nil
	}
}
