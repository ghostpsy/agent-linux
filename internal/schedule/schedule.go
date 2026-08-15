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
func Next(machineID string, lastScan, now time.Time) time.Time {
	if lastScan.IsZero() {
		return now.Add(newMachineDelay)
	}

	scheduled := midnightUTC(now).Add(DailyOffset(machineID))
	if !scheduled.After(lastScan) {
		scheduled = scheduled.Add(interval)
	}
	if scheduled.After(now) {
		return scheduled
	}

	// Overdue. Spread the catch-up the same way, so a fleet that rebooted
	// together does not arrive together.
	return now.Add(time.Duration(spread(machineID+":catchup", uint64(catchUpWindow))))
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
