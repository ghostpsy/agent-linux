//go:build linux

package schedule

import (
	"testing"
	"time"
)

const day = 24 * time.Hour

func TestDailyOffsetIsStableForAMachine(t *testing.T) {
	first := DailyOffset("m-abc-123")
	second := DailyOffset("m-abc-123")

	if first != second {
		t.Fatalf("the offset must not move between restarts: %v then %v", first, second)
	}
}

// Sixty servers must not all scan at 03:00. Without spreading them, a fleet
// arrives at our API and our LLM budget in one spike every night.
func TestDailyOffsetSpreadsAFleetAcrossTheDay(t *testing.T) {
	buckets := map[int]bool{}
	for _, id := range []string{"m-1", "m-2", "m-3", "m-4", "m-5", "m-6", "m-7", "m-8"} {
		buckets[int(DailyOffset(id).Hours())] = true
	}

	if len(buckets) < 5 {
		t.Fatalf("expected 8 machines to land in at least 5 different hours, got %d: %v", len(buckets), buckets)
	}
}

func TestDailyOffsetStaysInsideOneDay(t *testing.T) {
	for _, id := range []string{"m-1", "m-2", "zzz", ""} {
		if got := DailyOffset(id); got < 0 || got >= day {
			t.Errorf("%q: offset %v is outside a single day", id, got)
		}
	}
}

func TestNextIsTomorrowWhenTodaysScanAlreadyRan(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	lastScan := now.Add(-2 * time.Hour)

	next := Next("m-1", lastScan, now)

	if next.Before(now) {
		t.Fatalf("next scan %v is in the past", next)
	}
	if next.Sub(now) > day {
		t.Fatalf("next scan %v is more than a day away", next.Sub(now))
	}
}

// A server that was switched off for a week must not come back and fire a week
// of missed scans. One catch-up is the whole point.
func TestNextCatchesUpOnceAfterLongDowntime(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	lastScan := now.Add(-7 * day)

	next := Next("m-1", lastScan, now)

	if next.Before(now) {
		t.Fatalf("catch-up scan %v is in the past", next)
	}
	if next.Sub(now) > time.Hour {
		t.Fatalf("expected a missed scan to be caught up within the hour, got %v", next.Sub(now))
	}
}

// A rebooting fleet must not arrive together either. The catch-up delay is
// derived from the machine, so it is spread and still reproducible.
func TestCatchUpIsSpreadAcrossAFleet(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	lastScan := now.Add(-7 * day)

	delays := map[time.Duration]bool{}
	for _, id := range []string{"m-1", "m-2", "m-3", "m-4", "m-5", "m-6"} {
		delays[Next(id, lastScan, now).Sub(now).Round(time.Minute)] = true
	}

	if len(delays) < 4 {
		t.Fatalf("expected catch-up delays to be spread, got %d distinct values", len(delays))
	}
}

// Never scanned is not the same as overdue: a freshly installed agent scans
// almost at once, because the install just told the user it would.
func TestNextRunsAlmostImmediatelyForANewMachine(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

	next := Next("m-1", time.Time{}, now)

	if next.Sub(now) > 2*time.Minute {
		t.Fatalf("a new machine should scan almost at once, got %v", next.Sub(now))
	}
}
