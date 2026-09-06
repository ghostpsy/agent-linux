//go:build linux

package crypto_time

import "testing"

// A time daemon is found by looking for the process, not by asking systemd.
//
// The bug this was written for, measured end to end on an Ubuntu 14.04 host.
// Solve installed ntp, ntpd came up and stayed up, and the very next scan still
// reported "no time synchronization daemon" — so the fix was offered again, and
// again. The machine has no systemd, and `systemctl is-active` was the only
// question being asked.
//
// The process table is the honest place to look: a daemon is running or it is
// not, whatever started it. Upstart, sysvinit and systemd all agree on that.
func TestATimeDaemonIsFoundWithoutSystemd(t *testing.T) {
	running := map[string]bool{"ntpd": true}

	got := timesyncDaemonFrom(func(name string) bool { return running[name] })

	if got != "ntp" {
		t.Errorf("ntpd is running, so the daemon is ntp: got %q", got)
	}
}

func TestNoDaemonIsStillNone(t *testing.T) {
	if got := timesyncDaemonFrom(func(string) bool { return false }); got != "none" {
		t.Errorf("nothing is running, so: got %q, want none", got)
	}
}

// chrony and systemd-timesyncd are found the same way, so the answer does not
// depend on which init a machine happens to use.
func TestEveryKnownDaemonIsRecognised(t *testing.T) {
	for process, want := range map[string]string{
		"chronyd":           "chrony",
		"systemd-timesyncd": "systemd-timesyncd",
		"ntpd":              "ntp",
	} {
		got := timesyncDaemonFrom(func(name string) bool { return name == process })
		if got != want {
			t.Errorf("%s running: got %q, want %q", process, got, want)
		}
	}
}
