//go:build linux

package action

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// A machine can be busy with its own update for minutes: an `apt upgrade` a
// person started by hand, or unattended-upgrades on its daily run. Ten tries
// thirty seconds apart is five minutes of patience — long enough to outlast an
// ordinary update, short enough that a job never looks stuck for ever, and well
// inside the fifteen minutes after which the service gives up on a machine.
const (
	busyMaxAttempts = 10
	busyWait        = 30 * time.Second
)

// busySignals are the words these tools use when something else holds the lock.
//
// Matched as text because there is nothing better to match: apt, unattended-upgrade
// and dnf all exit 1 for this, the same as they do for a real failure, so the exit
// status cannot tell the two apart.
//
// Every one of these means the same thing, and it is the thing that makes a retry
// safe: the tool takes the lock before it does any work, so a command refused the
// lock has changed nothing at all.
var busySignals = []string{
	// unattended-upgrade
	"lock could not be acquired",
	"cache lock can not be acquired",
	"another package manager running",
	// apt-get and apt
	"could not get lock",
	"unable to acquire the dpkg frontend lock",
	"unable to lock the administration directory",
	"waiting for cache lock",
	// dnf and yum
	"existing lock /var/run/yum.pid",
	"another app is currently holding the yum lock",
	"waiting for process with pid",
	"failed to obtain the transaction lock",
}

// packageManagerBusy reports whether a step failed only because something else
// was using the package manager.
func packageManagerBusy(run CommandRun) bool {
	said := strings.ToLower(run.Stderr + "\n" + run.Stdout)
	for _, signal := range busySignals {
		if strings.Contains(said, signal) {
			return true
		}
	}
	return false
}

// waitBeforeRetry sleeps, and reports false if the run was called off while it
// slept. A cancelled job must not sit here for another half minute.
//
// deps.Sleep, not time.Sleep, so a test does not wait real minutes to prove the
// retry happened.
func waitBeforeRetry(ctx context.Context, deps Deps, d time.Duration) bool {
	return deps.Sleep(ctx, d) == nil
}

// busyGaveUp is what the person reading the report is told, in place of a lock
// message written for whoever wrote apt.
func busyGaveUp(said string) string {
	waited := time.Duration(busyMaxAttempts-1) * busyWait
	msg := fmt.Sprintf(
		"Another program on this machine is using the package manager. ghostpsy waited "+
			"%.0f minutes and it was still busy, so nothing was changed. Try again once that "+
			"program has finished.", waited.Minutes())
	if trimmed := strings.TrimSpace(said); trimmed != "" {
		return msg + "\n\nWhat the machine said:\n" + trimmed
	}
	return msg
}
