//go:build linux

// Package schedule decides when the agent scans.
//
// Everything here is derived from the machine's own identity rather than from
// randomness. That gives two properties at once: a fleet is spread out instead
// of arriving together, and the answer is the same after a restart, so a
// machine does not drift to a new time every time the service bounces.
package schedule

import (
	"hash/fnv"
	"time"
)

const (
	interval = 24 * time.Hour

	// catchUpWindow bounds how long after start a missed scan waits. Long
	// enough to spread a fleet that rebooted together, short enough that a
	// server which was off overnight reports back within the hour.
	catchUpWindow = time.Hour

	// newMachineDelay is what a freshly installed agent waits. The installer
	// has just told the user the machine is reporting, so it must be almost
	// immediate — but not zero, so a scripted rollout still staggers slightly.
	newMachineDelay = 90 * time.Second
)

// DailyOffset is how far after midnight UTC this machine scans.
//
// Without it, sixty servers all scan at 03:00 and arrive at our API and our
// LLM budget in one spike every night.
func DailyOffset(machineID string) time.Duration {
	return time.Duration(spread(machineID, uint64(interval)))
}

// Next reports when this machine should scan.
//
// A machine that has been switched off for a week gets one catch-up scan, not
// a week of missed ones.
//
// startedAt is when this agent process began, and the catch-up is anchored to
// it rather than to now. That matters: anchoring to now would push the target
// forward every time the loop asked, and an overdue scan would never arrive.
func Next(machineID string, lastScan, startedAt, now time.Time) time.Time {
	if lastScan.IsZero() {
		return startedAt.Add(newMachineDelay)
	}

	scheduled := midnightUTC(lastScan).Add(DailyOffset(machineID))
	if !scheduled.After(lastScan) {
		scheduled = scheduled.Add(interval)
	}
	if scheduled.After(now) {
		return scheduled
	}

	// Overdue. Spread the catch-up the same way as the daily slot, so a fleet
	// that rebooted together does not arrive together.
	return startedAt.Add(time.Duration(spread(machineID+":catchup", uint64(catchUpWindow))))
}

func midnightUTC(t time.Time) time.Time {
	utc := t.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

// spread maps a machine identity onto [0, limit) deterministically.
//
// The hash is mixed before use. FNV alone leaves neighbouring inputs close
// together, so hosts named in a series — web-01, web-02, web-03 — landed within
// a couple of hours of each other, which is the clustering this function exists
// to prevent.
func spread(key string, limit uint64) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return mix(h.Sum64()) % limit
}

// mix is the splitmix64 finalizer: it decorrelates inputs that differ only
// slightly, so sequential machine names do not produce sequential times.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// HeartbeatInterval is how often the agent says "I am still here".
//
// It is what lets the dashboard tell a switched-off server apart from a broken
// agent. At sixty servers it is about 5,800 tiny requests a day.
const HeartbeatInterval = 15 * time.Minute

// SolvePollInterval is how often the agent asks whether there is work for it.
//
// This is what decides how long a person waits after clicking approve, so it is
// the shortest rhythm in the loop. A minute per machine is about 1,440 questions
// a day each — more than the heartbeat's 96, and still a tiny request that reads
// one row. Much faster than this would buy a feeling of speed no ops fix needs;
// much slower and an approved fix would sit there while somebody watched.
//
// Nothing listens on the customer's server for this. The agent asks us, always.
const SolvePollInterval = time.Minute

// SolvePollBusyInterval is how often the agent asks while somebody is working with
// it, and SolveBusyWindow is how long that lasts after the last piece of work.
//
// One approved change is two round trips: the machine collects the job and sends
// back a preview, then collects the approval and runs it. At one question a minute
// that is a two minute wait for a change that takes a second, and the person spends
// it watching a spinner. Reported from a real session.
//
// The window is what keeps it quick while the person reads the preview and decides,
// which takes longer than one pass. It ends on its own, so a fleet of machines
// nobody is using goes back to one question a minute instead of six.
const (
	SolvePollBusyInterval = 10 * time.Second
	SolveBusyWindow       = 5 * time.Minute
)

// Action is what the service loop should do on this pass.
//
// Keeping the decision in a pure function is deliberate: the loop around it is
// then trivial, and every rule about when we touch a customer's server can be
// tested without touching one.
type Action struct {
	Scan      bool
	Heartbeat bool

	// Wait is how long to sleep when there is nothing to do. It is capped at
	// the Solve poll interval so the loop stays responsive: a daemon that sleeps
	// for twenty hours cannot be told anything, and Solve needs it awake to
	// collect work somebody has just approved.
	Wait time.Duration
}

// Decide reports what the loop should do now.
func Decide(machineID string, lastScan, lastHeartbeat, startedAt, now time.Time) Action {
	var act Action

	if !Next(machineID, lastScan, startedAt, now).After(now) {
		act.Scan = true
	}
	// A brand new agent reports in at once rather than waiting a quarter of an
	// hour to say hello.
	if lastHeartbeat.IsZero() || !now.Before(lastHeartbeat.Add(HeartbeatInterval)) {
		act.Heartbeat = true
	}
	if act.Scan || act.Heartbeat {
		return act
	}

	// Capped at the poll interval, not the heartbeat: the loop has to come back
	// often enough to notice an approved job, and it polls on every pass.
	act.Wait = min(Next(machineID, lastScan, startedAt, now).Sub(now), SolvePollInterval)
	if act.Wait <= 0 {
		act.Wait = SolvePollInterval
	}
	return act
}
