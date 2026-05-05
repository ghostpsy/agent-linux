//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/ghostpsy/agent-linux/internal/state"
)

// shouldRemindAboutVersion enforces the post-scan upgrade nudge cadence:
// fresh release → remind, same release within 7 days → stay quiet, different
// release → remind again immediately.

func TestShouldRemind_FirstTime(t *testing.T) {
	st := &state.AgentState{MachineUUID: "m"}
	if !shouldRemindAboutVersion(st, "0.41.0", time.Now()) {
		t.Fatal("expected reminder when state has never been written")
	}
}

func TestShouldRemind_QuietWithinAWeekForSameVersion(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	st := &state.AgentState{
		MachineUUID:               "m",
		LastUpdateNotifiedVersion: "0.41.0",
		LastUpdateNotifiedAt:      now.Add(-3 * 24 * time.Hour).Unix(),
	}
	if shouldRemindAboutVersion(st, "0.41.0", now) {
		t.Fatal("expected no reminder 3 days after the previous one for the same version")
	}
}

func TestShouldRemind_AfterAWeekForSameVersion(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	st := &state.AgentState{
		MachineUUID:               "m",
		LastUpdateNotifiedVersion: "0.41.0",
		LastUpdateNotifiedAt:      now.Add(-8 * 24 * time.Hour).Unix(),
	}
	if !shouldRemindAboutVersion(st, "0.41.0", now) {
		t.Fatal("expected reminder 8 days after the previous one")
	}
}

func TestShouldRemind_NewVersionRemindsImmediately(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	st := &state.AgentState{
		MachineUUID:               "m",
		LastUpdateNotifiedVersion: "0.40.0",
		LastUpdateNotifiedAt:      now.Add(-1 * time.Hour).Unix(),
	}
	if !shouldRemindAboutVersion(st, "0.41.0", now) {
		t.Fatal("expected reminder when target version differs from the last-notified one")
	}
}

func TestShouldRemind_EmptyTargetSilent(t *testing.T) {
	st := &state.AgentState{MachineUUID: "m"}
	if shouldRemindAboutVersion(st, "", time.Now()) {
		t.Fatal("expected no reminder for empty target version")
	}
}
