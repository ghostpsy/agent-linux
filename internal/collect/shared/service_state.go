//go:build linux

package shared

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/systemdutil"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const processLookupTimeout = 4 * time.Second

// UnitBaseName is a service's name without the ".service" systemd gives it.
//
// The two init systems spell the same service differently: systemd lists
// "apache2.service", sysvinit and Upstart list "apache2". Comparing the spellings
// as they come makes every match miss on one kind of machine.
func UnitBaseName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(name)), ".service")
}

// ServiceStateFromList reports what this machine's own service list already says
// about any of these units: "running", "stopped", or "" if it says nothing.
//
// Every posture used to ask for the systemd spelling only. On a machine with no
// systemd the answer was sitting in the payload and nothing could read it: the
// services block said apache2 was running, while apache_httpd_posture reported
// no service state at all. Six postures were blind this way on one Ubuntu 14.04
// host — apache, postfix, ftp, redis, mongodb and mysql.
func ServiceStateFromList(services []payload.ServiceEntry, want []string) string {
	wanted := make(map[string]struct{}, len(want))
	for _, n := range want {
		if base := UnitBaseName(n); base != "" {
			wanted[base] = struct{}{}
		}
	}
	for _, e := range services {
		if _, ok := wanted[UnitBaseName(e.Name)]; !ok {
			continue
		}
		if st := systemdutil.MapActiveStateForPosture(e.ActiveState); st == "running" || st == "stopped" {
			return st
		}
	}
	return ""
}

// ProcessRunningState reports "running" when one of these processes is in the
// process table, and "" when none of them is.
//
// It never answers "stopped". A name we do not find may be a service that is
// genuinely down, or the same service under a name this distribution chose
// differently — and reporting the second as "stopped" would be the very kind of
// confident wrong answer this function exists to replace. Saying "running" only
// when a process is really there adds knowledge without ever inventing any.
//
// This is the last question asked, after the machine's own service list and
// after systemd, because those two also say when something is stopped.
func ProcessRunningState(ctx context.Context, processes []string) string {
	return processRunningStateFrom(processes, func(name string) bool {
		return ProcessIsRunning(ctx, name)
	})
}

// processRunningStateFrom is the decision on its own, so it can be tested
// without needing the named processes to be running on the machine running the
// tests.
func processRunningStateFrom(processes []string, isRunning func(process string) bool) string {
	for _, name := range processes {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if isRunning(name) {
			return "running"
		}
	}
	return ""
}

// commMaxLen is how much of a process name Linux keeps.
//
// The kernel stores it in a 16-byte field: fifteen characters and a terminator.
// `pgrep -x` matches that stored name, and a longer pattern cannot ever equal it
// — pgrep says so itself and then matches nothing:
//
//	pgrep: pattern that searches for process name longer than 15 characters
//	       will result in zero matches
//
// So a pattern has to be cut the same way the kernel cut the name.
//
// This was not hypothetical. "systemd-timesyncd" is seventeen characters, so the
// check for it could never match anything. On a stock Ubuntu 24.04 — where
// timesyncd is the time daemon, is running, and has the clock right — the scan
// reported no time daemon at all, raised "no time synchronization daemon", and
// offered the same fix again after every scan.
const commMaxLen = 15

// ProcessIsRunning reports whether a process of exactly this name is running.
//
// -x, so "mysqld" does not also match "mysqld_safe": the wrapper can be up while
// the server it babysits is down, and reporting the wrapper as the service would
// be a confident wrong answer.
func ProcessIsRunning(ctx context.Context, name string) bool {
	pgrep, err := exec.LookPath("pgrep")
	if err != nil {
		return false
	}
	subCtx, cancel := context.WithTimeout(ctx, processLookupTimeout)
	defer cancel()
	return exec.CommandContext(subCtx, pgrep, "-x", CommName(name)).Run() == nil
}

// CommName is a process name cut to what the kernel stores, so it can be
// compared with what the kernel reports.
func CommName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) <= commMaxLen {
		return name
	}
	return name[:commMaxLen]
}
