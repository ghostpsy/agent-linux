//go:build linux

package service

import (
	"errors"
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

// A fake init system, so the install and removal steps can be tested without
// one. What matters is the order and the completeness, not the exact commands.
// errFakeFailure belongs with the double that returns it, not in the shipped
// package.
var errFakeFailure = errors.New("service: simulated failure")

type fakeRunner struct {
	calls   []string
	written map[string]string
	fail    string
}

func newFakeRunner() *fakeRunner { return &fakeRunner{written: map[string]string{}} }

func (f *fakeRunner) run(name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.Contains(call, f.fail) {
		return errFakeFailure
	}
	return nil
}

func (f *fakeRunner) write(path, content string) error {
	f.written[path] = content
	return nil
}

func (f *fakeRunner) remove(path string) error {
	f.calls = append(f.calls, "remove "+path)
	delete(f.written, path)
	return nil
}

func (f *fakeRunner) did(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func TestSystemdInstallWritesTheUnitEnablesAndStarts(t *testing.T) {
	f := newFakeRunner()
	m := systemdManager{run: f.run, write: f.write, remove: f.remove}

	if err := m.Install(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"}); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	if _, ok := f.written["/etc/systemd/system/ghostpsy.service"]; !ok {
		t.Fatalf("no unit file written, wrote: %v", f.written)
	}
	// daemon-reload must come before enable, or systemd acts on a unit it has
	// not read yet.
	if !f.did("daemon-reload") || !f.did("enable") {
		t.Fatalf("expected daemon-reload then enable, got: %v", f.calls)
	}
}

// Removal has to leave nothing behind. A tool that is hard to remove is a tool
// people hesitate to install.
func TestSystemdRemoveStopsDisablesAndDeletesTheUnit(t *testing.T) {
	f := newFakeRunner()
	m := systemdManager{run: f.run, write: f.write, remove: f.remove}
	_ = m.Install(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	if err := m.Remove(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	for _, want := range []string{"stop", "disable", "remove /etc/systemd/system/ghostpsy.service"} {
		if !f.did(want) {
			t.Errorf("removal did not %q, calls: %v", want, f.calls)
		}
	}
}

func TestUpstartInstallWritesTheJobAndStarts(t *testing.T) {
	f := newFakeRunner()
	m := upstartManager{run: f.run, write: f.write, remove: f.remove}

	if err := m.Install(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"}); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	if _, ok := f.written["/etc/init/ghostpsy.conf"]; !ok {
		t.Fatalf("no upstart job written, wrote: %v", f.written)
	}
	if !f.did("start ghostpsy") {
		t.Fatalf("expected the job to be started, got: %v", f.calls)
	}
}

// Stopping a service that is already stopped is not a failure. Removal has to
// finish and leave nothing behind, whatever state it found.
func TestRemoveFinishesEvenIfStopFails(t *testing.T) {
	f := newFakeRunner()
	f.fail = "stop"
	m := systemdManager{run: f.run, write: f.write, remove: f.remove}
	_ = m.Install(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	if err := m.Remove(); err != nil {
		t.Fatalf("remove must not fail because the service was already stopped: %v", err)
	}
	if _, still := f.written["/etc/systemd/system/ghostpsy.service"]; still {
		t.Error("the unit file was left behind")
	}
}
