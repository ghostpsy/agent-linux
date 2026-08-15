//go:build linux

package service

import (
	"os"
	"strings"
)

// Kind is the init system this host uses.
type Kind int

const (
	Unsupported Kind = iota
	Systemd
	Upstart
)

func (k Kind) String() string {
	switch k {
	case Systemd:
		return "systemd"
	case Upstart:
		return "upstart"
	default:
		return "unsupported"
	}
}

// Detect reports which init system is running here.
//
// It reads /proc/1/comm rather than testing for /run/systemd/system, matching
// the detection already used by the services collector. That check is the
// honest one: /run/systemd/system exists in places systemd is not actually
// running pid 1, and two detectors that disagree is a bug waiting for a
// customer to find.
func Detect() Kind {
	return detectFrom(pidOneName(), fileExists)
}

func detectFrom(pidOne string, exists func(string) bool) Kind {
	if pidOne == "systemd" {
		return Systemd
	}
	if exists("/sbin/initctl") || exists("/usr/sbin/initctl") {
		return Upstart
	}
	return Unsupported
}

func pidOneName() string {
	b, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
