//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghostpsy/agent-linux/internal/schedule"
)

func fixedDeps() (*serveDeps, *int, *int) {
	scans, beats := 0, 0
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		now:       func() time.Time { return now },
		scan:      func(context.Context) error { scans++; return nil },
		heartbeat: func(context.Context) error { beats++; return nil },
		sleep:     func(context.Context, time.Duration) error { return nil },
	}
	return d, &scans, &beats
}

func TestServePassScansWhenOneIsDue(t *testing.T) {
	d, scans, _ := fixedDeps()
	d.lastScan = d.now().Add(-7 * 24 * time.Hour)
	d.startedAt = d.now().Add(-2 * time.Hour)
	d.lastHeartbeat = d.now()

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *scans != 1 {
		t.Fatalf("expected exactly one scan, got %d", *scans)
	}
}

// A scan that fails must not stop the service. The machine would go silent for
// a reason nobody could see, which is the failure this whole epic exists to
// remove.
func TestServePassSurvivesAFailingScan(t *testing.T) {
	d, _, _ := fixedDeps()
	d.lastScan = d.now().Add(-7 * 24 * time.Hour)
	d.startedAt = d.now().Add(-2 * time.Hour)
	d.lastHeartbeat = d.now()
	d.scan = func(context.Context) error { return errors.New("network unreachable") }

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("a failing scan must not stop the loop, got: %v", err)
	}
}

// A failed scan must not be recorded as a success either, or the machine would
// wait a full day before trying again.
func TestServePassDoesNotRecordAFailedScan(t *testing.T) {
	d, _, _ := fixedDeps()
	before := d.now().Add(-7 * 24 * time.Hour)
	d.lastScan = before
	d.startedAt = d.now().Add(-2 * time.Hour)
	d.lastHeartbeat = d.now()
	d.scan = func(context.Context) error { return errors.New("network unreachable") }

	_ = servePass(context.Background(), d)

	if !d.lastScan.Equal(before) {
		t.Fatalf("a failed scan must not update lastScan, moved to %v", d.lastScan)
	}
}

func TestServePassSleepsWhenNothingIsDue(t *testing.T) {
	d, scans, beats := fixedDeps()
	d.lastScan = d.now()
	d.lastHeartbeat = d.now()
	slept := time.Duration(0)
	d.sleep = func(_ context.Context, dur time.Duration) error { slept = dur; return nil }

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *scans != 0 || *beats != 0 {
		t.Fatalf("expected nothing to run, got %d scans and %d heartbeats", *scans, *beats)
	}
	if slept <= 0 {
		t.Fatalf("expected the loop to wait, slept %v", slept)
	}
}

// Found on a real host, not by a unit test: a failing scan is correctly not
// recorded, so the next pass still finds one due — and the loop spun, retrying
// every two seconds forever. On a server with no network that is a subprocess
// storm that never stops.
func TestServePassBacksOffAfterAFailedScan(t *testing.T) {
	d, _, _ := fixedDeps()
	d.lastScan = d.now().Add(-7 * 24 * time.Hour)
	d.startedAt = d.now().Add(-2 * time.Hour)
	d.lastHeartbeat = d.now()
	d.scan = func(context.Context) error { return errors.New("network unreachable") }
	slept := time.Duration(0)
	d.sleep = func(_ context.Context, dur time.Duration) error { slept = dur; return nil }

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slept < time.Minute {
		t.Fatalf("expected a real wait after a failed scan, slept %v", slept)
	}
}

// A scan that worked must not be followed by the retry back-off — the machine
// should go back to its normal daily rhythm.
func TestServePassDoesNotBackOffAfterASuccessfulScan(t *testing.T) {
	d, _, _ := fixedDeps()
	d.lastScan = d.now().Add(-7 * 24 * time.Hour)
	d.startedAt = d.now().Add(-2 * time.Hour)
	d.lastHeartbeat = d.now()
	slept := time.Duration(-1)
	d.sleep = func(_ context.Context, dur time.Duration) error { slept = dur; return nil }

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slept > 0 && slept >= retryDelay {
		t.Fatalf("a successful scan must not trigger the retry back-off, slept %v", slept)
	}
}

// The scan path got a back-off; the heartbeat path did not. A failed heartbeat
// leaves lastHeartbeat unset, so Decide asks for another one immediately and
// Wait stays zero — a tight loop that burns a core forever. Found by review,
// not by the earlier tests, because they only checked the scan path.
func TestServePassBacksOffAfterAFailedHeartbeat(t *testing.T) {
	d, _, _ := fixedDeps()
	d.lastScan = d.now()
	d.lastHeartbeat = time.Time{}
	d.heartbeat = func(context.Context) error { return errors.New("permission denied") }
	slept := time.Duration(0)
	d.sleep = func(_ context.Context, dur time.Duration) error { slept = dur; return nil }

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slept < time.Minute {
		t.Fatalf("a failed heartbeat must not spin the loop, slept %v", slept)
	}
}

// Solve is why the loop wakes in minutes. Every pass asks the service whether
// there is work, because that question is what makes an approved fix arrive
// without anybody logging in.
func TestEveryPassAsksTheServiceForWork(t *testing.T) {
	asked := 0
	now := time.Now().UTC()
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  now,
		now:       func() time.Time { return now },
		scan:      func(context.Context) error { return nil },
		heartbeat: func(context.Context) error { return nil },
		sleep:     func(context.Context, time.Duration) error { return nil },
		pollSolve: func(context.Context) error { asked++; return nil },
	}

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if asked != 1 {
		t.Errorf("expected one question to the service, got %d", asked)
	}
}

// A machine whose Solve channel is broken must keep scanning and keep saying it
// is alive. Solve is the newest part of the agent and the least essential: it
// must never be able to take the rest of it down.
func TestABrokenSolveChannelDoesNotStopTheAgent(t *testing.T) {
	scans := 0
	beats := 0
	now := time.Now().UTC()
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  time.Time{},
		now:       func() time.Time { return now.Add(2 * time.Minute) },
		scan:      func(context.Context) error { scans++; return nil },
		heartbeat: func(context.Context) error { beats++; return nil },
		sleep:     func(context.Context, time.Duration) error { return nil },
		pollSolve: func(context.Context) error { return errors.New("connection refused") },
	}

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("a broken solve channel must not stop the loop: %v", err)
	}

	if scans != 1 || beats != 1 {
		t.Errorf("the rest of the agent must carry on, got %d scans and %d beats", scans, beats)
	}
}

// A failed scan must not silence the Solve channel. Found on a real machine: the
// scan hit a rate limit, the loop slept fifteen minutes, and nobody could have
// had an approved fix collected in under a quarter of an hour for a reason that
// had nothing to do with Solve.
func TestAFailedScanDoesNotDelayTheNextQuestionToTheService(t *testing.T) {
	now := time.Now().UTC()
	slept := time.Duration(0)
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  time.Time{},
		now:       func() time.Time { return now.Add(2 * time.Minute) },
		scan:      func(context.Context) error { return errors.New("429 Too Many Requests") },
		heartbeat: func(context.Context) error { return nil },
		pollSolve: func(context.Context) error { return nil },
		sleep:     func(_ context.Context, d time.Duration) error { slept = d; return nil },
	}

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slept > schedule.SolvePollInterval {
		t.Errorf("slept %v after a failed scan, so solve work would wait that long too", slept)
	}
}

// The reason that sleep existed: a failed scan is not recorded, so the next pass
// still finds one due. Without something holding it back the loop spawned a scan
// every two seconds, forever. It must not come back.
func TestAFailedScanIsNotRetriedImmediately(t *testing.T) {
	now := time.Now().UTC()
	attempts := 0
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  time.Time{},
		now:       func() time.Time { return now.Add(2 * time.Minute) },
		scan:      func(context.Context) error { attempts++; return errors.New("no network") },
		heartbeat: func(context.Context) error { return nil },
		pollSolve: func(context.Context) error { return nil },
		sleep:     func(context.Context, time.Duration) error { return nil },
	}

	for range 5 {
		if err := servePass(context.Background(), d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if attempts != 1 {
		t.Errorf("expected one attempt until the retry falls due, got %d", attempts)
	}
}

func TestAFailedScanIsRetriedOnceTheDelayHasPassed(t *testing.T) {
	now := time.Now().UTC()
	attempts := 0
	clock := now.Add(2 * time.Minute)
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  time.Time{},
		now:       func() time.Time { return clock },
		scan:      func(context.Context) error { attempts++; return errors.New("no network") },
		heartbeat: func(context.Context) error { return nil },
		pollSolve: func(context.Context) error { return nil },
		sleep:     func(context.Context, time.Duration) error { return nil },
	}

	_ = servePass(context.Background(), d)
	clock = clock.Add(retryDelay + time.Second)
	_ = servePass(context.Background(), d)

	if attempts != 2 {
		t.Errorf("expected a second attempt after %v, got %d", retryDelay, attempts)
	}
}
