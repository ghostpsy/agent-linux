//go:build linux

package main

import "os"

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
