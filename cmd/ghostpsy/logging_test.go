//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Nothing in the agent set a log level, so slog's default hid every Debug line.
// A heartbeat that fails is the reason a machine looks dead in the dashboard,
// and it was logged at Debug — invisible, with no way to turn it on.
func TestLogLevelCanBeTurnedUp(t *testing.T) {
	cases := map[string]slog.Level{
		"":      slog.LevelInfo,
		"debug": slog.LevelDebug,
		"DEBUG": slog.LevelDebug,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"noise": slog.LevelInfo,
	}

	for given, want := range cases {
		if got := logLevel(given); got != want {
			t.Errorf("logLevel(%q) = %v, want %v", given, got, want)
		}
	}
}

// A failed heartbeat has to be visible without anyone turning anything on. The
// machine goes quiet in the dashboard either way; the log is the only place that
// says why.
func TestAFailedHeartbeatIsVisibleByDefault(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(previous)

	now := time.Now().UTC()
	d := &serveDeps{
		machineID: "m-1",
		startedAt: now,
		lastScan:  now,
		now:       func() time.Time { return now },
		scan:      func(context.Context) error { return nil },
		heartbeat: func(context.Context) error { return errors.New("connection refused") },
		sleep:     func(context.Context, time.Duration) error { return nil },
	}

	if err := servePass(context.Background(), d); err != nil {
		t.Fatalf("a failed heartbeat must not stop the loop: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "heartbeat") {
		t.Errorf("a failed heartbeat produced nothing at the default level:\n%s", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("the reason must be in the log, got:\n%s", out)
	}
}
