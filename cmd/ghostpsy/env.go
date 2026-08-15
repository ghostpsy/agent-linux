//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// envSelfPathOverride lets tests point the agent at a binary somewhere else.
const envSelfPathOverride = "GHOSTPSY_SELF_PATH"

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// defaultAPIBaseURL is the public service. It lives here rather than being
// repeated in scan, register and serve, so the three can never disagree about
// where the agent talks to.
const defaultAPIBaseURL = "https://api.ghostpsy.com"

// resolveSelfPath returns this binary's real path.
//
// It follows symlinks, which matters: the sudoers grant pins
// /usr/local/bin/ghostpsy exactly, and a unit or a delegated read pointing at
// a link target would not be covered by it.
func resolveSelfPath() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envSelfPathOverride)); v != "" {
		return v, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if abs, err := filepath.EvalSymlinks(p); err == nil {
		return abs, nil
	}
	return p, nil
}
