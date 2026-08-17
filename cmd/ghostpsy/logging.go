//go:build linux

package main

import (
	"log/slog"
	"os"
	"strings"
)

// envLogLevel turns the agent's logging up. Nothing set a level before, so slog
// used its default and every Debug line in the agent was unreachable — there was
// no way at all to see them on a customer's server.
const envLogLevel = "GHOSTPSY_LOG_LEVEL"

// logLevel reads a level name. Anything unrecognised means the normal level: a
// typo in a variable should not silence a server.
func logLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// setUpLogging installs the default logger for the whole process.
func setUpLogging() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(os.Getenv(envLogLevel)),
	})
	slog.SetDefault(slog.New(handler))
}
