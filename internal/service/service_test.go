//go:build linux

package service

import (
	"strings"
	"testing"
)

// The agent must run as a service on hosts far older than systemd, because the
// neglected servers our users inherited are exactly those hosts. One interface,
// one implementation per manager, and nothing else in the agent knows which is
// in use.
func TestSystemdUnitRunsAsTheLockedUserAndRestarts(t *testing.T) {
	unit := systemdUnit(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	for _, want := range []string{
		"User=ghostpsy",
		"Restart=always",
		"ExecStart=/usr/local/bin/ghostpsy serve",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit missing %q:\n%s", want, unit)
		}
	}
}

// NoNewPrivileges would break sudo outright, and the agent reaches every
// privileged read through sudo. Shipping it would silently empty the scan.
func TestSystemdUnitDoesNotBreakSudo(t *testing.T) {
	unit := systemdUnit(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	// Only active directives count. The unit deliberately names these in a
	// comment to explain why they are absent, and a comment is not a setting.
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, forbidden := range []string{"NoNewPrivileges=yes", "NoNewPrivileges=true", "ProtectSystem=strict"} {
			if line == forbidden {
				t.Errorf("unit sets %q, which breaks the sudo the agent depends on", forbidden)
			}
		}
	}
}

// Upstart is what RHEL/CentOS 6 uses. respawn is the whole reason it is
// supported: without it a crashed agent stays dead and the machine goes quiet.
func TestUpstartJobRespawnsAndRunsAsTheLockedUser(t *testing.T) {
	job := upstartJob(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	if !strings.Contains(job, "respawn") {
		t.Errorf("upstart job must respawn a crashed agent:\n%s", job)
	}
	if !strings.Contains(job, "setuid ghostpsy") {
		t.Errorf("upstart job must drop to the locked user:\n%s", job)
	}
	if !strings.Contains(job, "/usr/local/bin/ghostpsy serve") {
		t.Errorf("upstart job missing the command:\n%s", job)
	}
}

// There must be exactly one init-system detector in this codebase. A second one
// that disagrees with the first is a bug waiting for a customer to find.
func TestDetectPrefersSystemdWhenItIsPidOne(t *testing.T) {
	got := detectFrom("systemd", func(string) bool { return true })

	if got != Systemd {
		t.Fatalf("expected Systemd when pid 1 is systemd, got %v", got)
	}
}

func TestDetectFallsBackToUpstartWhenInitctlExists(t *testing.T) {
	got := detectFrom("init", func(path string) bool { return path == "/sbin/initctl" })

	if got != Upstart {
		t.Fatalf("expected Upstart on a host with initctl and no systemd, got %v", got)
	}
}

// A host with neither is not supported, and must say so rather than guess. A
// wrong guess installs a service definition the host will never read.
func TestDetectReportsUnsupportedRatherThanGuessing(t *testing.T) {
	got := detectFrom("init", func(string) bool { return false })

	if got != Unsupported {
		t.Fatalf("expected Unsupported when no init system is recognised, got %v", got)
	}
}
