//go:build linux

package shared

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// TestAServiceIsFoundWhateverInitSystemNamedIt is the bug this file exists for.
//
// On a real Ubuntu 14.04 host the services block said apache2 was running and
// apache_httpd_posture.service_state was empty at the same time, in the same
// payload. The posture asked for "apache2.service" because that is how systemd
// spells it, and sysvinit had listed it as "apache2".
func TestAServiceIsFoundWhateverInitSystemNamedIt(t *testing.T) {
	sysvinit := []payload.ServiceEntry{{Name: "apache2", Manager: "sysvinit", ActiveState: "running"}}
	if got := ServiceStateFromList(sysvinit, []string{"apache2.service", "httpd.service"}); got != "running" {
		t.Fatalf("sysvinit name against a systemd want: got %q, want %q", got, "running")
	}

	systemd := []payload.ServiceEntry{{Name: "apache2.service", Manager: "systemd", ActiveState: "active"}}
	if got := ServiceStateFromList(systemd, []string{"apache2"}); got != "running" {
		t.Fatalf("systemd name against a bare want: got %q, want %q", got, "running")
	}
}

func TestServiceStateReportsStoppedAsWellAsRunning(t *testing.T) {
	services := []payload.ServiceEntry{{Name: "redis-server", ActiveState: "inactive"}}
	if got := ServiceStateFromList(services, []string{"redis-server.service"}); got != "stopped" {
		t.Fatalf("got %q, want %q", got, "stopped")
	}
}

func TestServiceStateSaysNothingWhenItKnowsNothing(t *testing.T) {
	services := []payload.ServiceEntry{{Name: "nginx", ActiveState: "running"}}
	if got := ServiceStateFromList(services, []string{"apache2.service"}); got != "" {
		t.Fatalf("a service we did not ask about: got %q, want empty", got)
	}
	if got := ServiceStateFromList(nil, []string{"apache2.service"}); got != "" {
		t.Fatalf("no service list at all: got %q, want empty", got)
	}
	// A state we cannot map is not an answer, and must not be reported as one.
	odd := []payload.ServiceEntry{{Name: "apache2", ActiveState: "activating"}}
	if got := ServiceStateFromList(odd, []string{"apache2.service"}); got != "" {
		t.Fatalf("an unmappable state: got %q, want empty", got)
	}
}

func TestUnitBaseNameIgnoresSpellingAndSpacing(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"apache2.service", "apache2"},
		{"apache2", "apache2"},
		{"  Apache2.service  ", "apache2"},
		{"", ""},
	} {
		if got := UnitBaseName(tc.in); got != tc.want {
			t.Errorf("UnitBaseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProcessStateNeverSaysStopped(t *testing.T) {
	// Nothing is running. The answer is "I do not know", not "it is stopped":
	// a name we cannot find may be the same service under a name this
	// distribution chose differently.
	if got := processRunningStateFrom([]string{"mysqld", "mariadbd"}, func(string) bool { return false }); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestProcessStateFindsTheSecondNameToo(t *testing.T) {
	asked := []string{}
	isRunning := func(name string) bool {
		asked = append(asked, name)
		return name == "mariadbd"
	}
	if got := processRunningStateFrom([]string{"mysqld", "mariadbd"}, isRunning); got != "running" {
		t.Fatalf("got %q, want %q", got, "running")
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v, want both names tried", asked)
	}
}

func TestProcessStateWithNothingToLookFor(t *testing.T) {
	if got := processRunningStateFrom(nil, func(string) bool { return true }); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := processRunningStateFrom([]string{"   "}, func(string) bool { return true }); got != "" {
		t.Fatalf("a blank name must not be looked up: got %q, want empty", got)
	}
}

// TestALongProcessNameIsCutTheWayTheKernelCutsIt is the false positive this
// exists for.
//
// Linux keeps a process name in a 16-byte field: fifteen characters and a
// terminator. `pgrep -x` compares against that stored name, so a longer pattern
// matches nothing at all — pgrep even says so and then matches nothing anyway.
//
// "systemd-timesyncd" is seventeen characters. On a stock Ubuntu 24.04, where
// timesyncd is the time daemon and had the clock correctly synchronised, the scan
// reported no time daemon, raised "no time synchronization daemon", and Solve
// offered the same fix again after every scan. The machine was never wrong.
func TestALongProcessNameIsCutTheWayTheKernelCutsIt(t *testing.T) {
	// Measured on the machine: /proc/477/comm held exactly this.
	const whatTheKernelKept = "systemd-timesyn"

	if got := CommName("systemd-timesyncd"); got != whatTheKernelKept {
		t.Errorf("CommName(%q) = %q, want %q", "systemd-timesyncd", got, whatTheKernelKept)
	}
	if len(CommName("systemd-timesyncd")) != commMaxLen {
		t.Errorf("a cut name is %d characters, want %d", len(CommName("systemd-timesyncd")), commMaxLen)
	}
}

func TestAShortProcessNameIsLeftAlone(t *testing.T) {
	for _, name := range []string{"ntpd", "chronyd", "mysqld", "apache2", "redis-server"} {
		if got := CommName(name); got != name {
			t.Errorf("CommName(%q) = %q, want it unchanged", name, got)
		}
	}
	// Exactly at the limit is not too long.
	fifteen := "123456789012345"
	if got := CommName(fifteen); got != fifteen {
		t.Errorf("CommName(%q) = %q, want it unchanged", fifteen, got)
	}
}
