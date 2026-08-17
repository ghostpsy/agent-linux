//go:build linux

package service

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Starting a service is not the same as it running.
//
// `systemctl enable --now` returns success as soon as systemd accepts the unit.
// If the process then dies, systemd puts it into auto-restart and the exit code
// we already read stays zero. On a real Rocky 9 machine that produced:
//
//	ok  Start the ghostpsy service (systemd)
//	Done. This server is now reporting.
//
// while the service crash-looped on 203/EXEC and never reported anything. It is
// the same mistake as trusting a chown that left a file the service could not
// read: checking that a command was accepted instead of checking that the thing
// it was asked for happened.
//
// So the install asks again, a moment later, and asks the init system rather than
// itself.

// settleFn waits between looks. Injected so a test does not sleep.
type settleFn func(time.Duration)

// outputFn runs a command and returns what it printed.
type outputFn func(name string, args ...string) (string, error)

const (
	// confirmAttempts is how many times to ask whether the service came up.
	// A slow machine can take a couple of seconds; a broken one never will.
	confirmAttempts = 6

	// confirmGap is the wait between looks.
	confirmGap = 1500 * time.Millisecond
)

// noSettle is the settle function for tests: no waiting at all.
func noSettle(time.Duration) {}

func realSettle(d time.Duration) { time.Sleep(d) }

// confirmRunning asks the init system whether the service is really up, and says
// what is wrong in plain words when it is not.
//
// state and detail are closures because the two init systems ask completely
// different questions. Keeping the loop, the waiting and the wording here means
// only the question differs between them.
func confirmRunning(settle settleFn, state func() string, running func(string) bool, detail func() string) error {
	var last string

	for attempt := range confirmAttempts {
		last = strings.TrimSpace(state())
		if running(last) {
			return nil
		}
		if attempt < confirmAttempts-1 {
			settle(confirmGap)
		}
	}

	return fmt.Errorf("the ghostpsy service was installed but is not running: %s.\n%s",
		describeState(last), explainWhy(detail()))
}

func describeState(state string) string {
	switch {
	case state == "":
		return "the init system did not say what state it is in"
	case strings.Contains(state, "activating"):
		return "it starts and then stops again, over and over"
	default:
		return "it is " + state
	}
}

// explainWhy turns what the init system printed into something to act on.
//
// 203/EXEC on a machine with SELinux has one overwhelmingly likely cause, and a
// message that does not name it sends a sysadmin looking in entirely the wrong
// place — at the binary's permissions, which are fine.
func explainWhy(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return "ghostpsy could not find out why. Try: systemctl status ghostpsy"
	}

	if strings.Contains(detail, "203") {
		return "The init system could not run the binary at all (203/EXEC). On a server with " +
			"SELinux this usually means the file has the wrong security label, which happens " +
			"when it was copied somewhere else first and moved into place. Fix it with:\n" +
			"  restorecon -v /usr/local/bin/ghostpsy\n" +
			"What the init system said: " + firstLines(detail, 3)
	}
	return "What the init system said: " + firstLines(detail, 4)
}

func firstLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " / ")
}

// commandOutput runs a command and returns its combined output. The error is kept
// separate from the text: a failing `systemctl is-active` still prints the state,
// and the state is the part that matters.
func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec // fixed names from this package
	return string(out), err
}
