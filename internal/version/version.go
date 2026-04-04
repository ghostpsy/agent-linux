// Package version holds link-time build metadata (release binaries and Makefile set these via -ldflags).
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the agent semantic version (e.g. 0.1.2). Release and local Makefile builds set this via -ldflags.
	Version = "dev"
	// ReleaseDate is the build date in UTC YYYY-MM-DD. Set at link time for reproducible labeling.
	ReleaseDate = "unknown"
)

// DisplayGOARCH matches published artifact names (linux/i386, not linux/386).
func DisplayGOARCH() string {
	if runtime.GOARCH == "386" {
		return "i386"
	}
	return runtime.GOARCH
}

// Summary returns human-readable version, release date, and OS/architecture.
func Summary() string {
	return fmt.Sprintf("version %s\nrelease date %s\narchitecture %s/%s",
		Version, ReleaseDate, runtime.GOOS, DisplayGOARCH())
}
