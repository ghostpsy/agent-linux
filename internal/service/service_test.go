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
	if !strings.Contains(job, "ghostpsy") {
		t.Errorf("upstart job must drop to the locked user:\n%s", job)
	}
	if !strings.Contains(job, "/usr/local/bin/ghostpsy serve") {
		t.Errorf("upstart job missing the command:\n%s", job)
	}
}

// The setuid stanza arrived in Upstart 1.4. CentOS 6 ships 0.6.5, which does not
// merely ignore it — it rejects the whole job, so `initctl start ghostpsy`
// answers "Unknown job: ghostpsy" while the file sits there looking correct.
//
// Measured on an emulated CentOS 6.10 (upstart 0.6.5): deleting the setuid line
// from the very same file made the job load. Every install on the one
// distribution Upstart exists for had a service that could never start, and
// respawn — the reason Upstart is supported at all — never ran once.
func TestUpstartJobAvoidsStanzasCentOS6Rejects(t *testing.T) {
	job := upstartJob(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	for _, line := range strings.Split(job, "\n") {
		field := strings.Fields(strings.TrimSpace(line))
		if len(field) == 0 || strings.HasPrefix(field[0], "#") {
			continue
		}
		switch field[0] {
		case "setuid", "setgid":
			t.Errorf("upstart 0.6.5 rejects the whole job over %q:\n%s", field[0], job)
		}
	}
}

// Dropping privilege still has to happen, by a means 0.6.5 understands. exec su
// replaces the shell with the agent, so Upstart keeps supervising the real
// process and respawn still means something.
func TestUpstartJobDropsPrivilegeWithSu(t *testing.T) {
	job := upstartJob(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	if !strings.Contains(job, "exec su ") {
		t.Errorf("the job must drop privilege with su, which 0.6.5 supports:\n%s", job)
	}
	if !strings.Contains(job, "exec /usr/local/bin/ghostpsy serve") {
		t.Errorf("su must exec the agent, so Upstart supervises it and not a shell:\n%s", job)
	}
}

// The environment has to survive the change of user, or a machine set up against
// a staging server silently reports to the public one — the same bug the systemd
// unit already carries a fix for. su resets the environment unless told not to.
func TestUpstartJobKeepsTheEnvironmentAcrossSu(t *testing.T) {
	job := upstartJob(Spec{
		ExecStart: "/usr/local/bin/ghostpsy serve",
		User:      "ghostpsy",
		Env:       []string{"GHOSTPSY_API_URL=http://10.0.0.1:8000"},
	})

	if !strings.Contains(job, "env GHOSTPSY_API_URL=http://10.0.0.1:8000") {
		t.Errorf("the job must declare the environment:\n%s", job)
	}
	if !strings.Contains(job, "su -m") {
		t.Errorf("su must preserve the environment, or the declared value is lost:\n%s", job)
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

// The agent registers with one server and then reports to another unless the
// service carries the address. Found on a test VM: setup was told to use a
// local API, the machine registered there, and the daemon then talked to the
// public service because the unit said nothing about it.
func TestSystemdUnitCarriesTheEnvironmentItWasGiven(t *testing.T) {
	unit := systemdUnit(Spec{
		ExecStart: "/usr/local/bin/ghostpsy serve",
		User:      "ghostpsy",
		Env:       []string{"GHOSTPSY_API_URL=http://192.168.64.1:8000"},
	})

	if !strings.Contains(unit, `Environment="GHOSTPSY_API_URL=http://192.168.64.1:8000"`) {
		t.Errorf("the unit must pass the address on to the service:\n%s", unit)
	}
}

// Nothing to carry must produce no Environment line at all. An empty directive
// is noise in a file whose value is that a person can read it.
func TestSystemdUnitHasNoEnvironmentLineWhenThereIsNothingToPass(t *testing.T) {
	unit := systemdUnit(Spec{ExecStart: "/usr/local/bin/ghostpsy serve", User: "ghostpsy"})

	if strings.Contains(unit, "Environment") {
		t.Errorf("no environment was given, so the unit must not mention one:\n%s", unit)
	}
}

// Upstart has its own syntax for the same thing, and CentOS 6 is exactly the
// kind of host someone would point at a self-hosted server.
func TestUpstartJobCarriesTheEnvironmentItWasGiven(t *testing.T) {
	job := upstartJob(Spec{
		ExecStart: "/usr/local/bin/ghostpsy serve",
		User:      "ghostpsy",
		Env:       []string{"GHOSTPSY_API_URL=http://192.168.64.1:8000"},
	})

	if !strings.Contains(job, "env GHOSTPSY_API_URL=http://192.168.64.1:8000") {
		t.Errorf("the job must pass the address on to the service:\n%s", job)
	}
}
