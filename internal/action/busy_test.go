//go:build linux

package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// theLockMessage is what a real Ubuntu 24.04 said when an `apt upgrade` a person
// had started by hand was still running:
//
//	$ sudo unattended-upgrade --dry-run --verbose
//	Starting unattended upgrades script
//	Lock could not be acquired (another package manager running?)
//	Cache lock can not be acquired, exiting
//	exit status 1
const theLockMessage = "Starting unattended upgrades script\n" +
	"Lock could not be acquired (another package manager running?)\n" +
	"Cache lock can not be acquired, exiting"

// busyThenFree fails with the lock message for the first n calls, then works.
type busyThenFree struct {
	busyFor int
	calls   int
	slept   int
}

func (b *busyThenFree) run(_ context.Context, _ privexec.ID, _ privexec.Values) (privexec.Result, error) {
	b.calls++
	if b.calls <= b.busyFor {
		return privexec.Result{ExitCode: 1, Stderr: []byte(theLockMessage)}, errBusy{}
	}
	return privexec.Result{ExitCode: 0, Stdout: []byte("done")}, nil
}

type errBusy struct{}

func (errBusy) Error() string { return "exit status 1" }

func (b *busyThenFree) deps() Deps {
	d := testDeps(&fakeExec{})
	d.Exec = b.run
	d.Sleep = func(context.Context, time.Duration) error { b.slept++; return nil }
	return d
}

// A machine busy with its own update must not lose the job.
//
// The bug this was written for. An `apt upgrade` started by hand held the lock,
// so the very first step of enable_automatic_security_updates failed, and the
// whole job was thrown away over a machine that was merely occupied. Nothing had
// been changed and nothing was wrong with it.
func TestAStepBlockedByTheLockIsTriedAgain(t *testing.T) {
	b := &busyThenFree{busyFor: 2}
	declareForTest(t, simpleAction("busy_action"))

	report := Run(context.Background(), b.deps(), Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "busy_action"}},
	})

	if !report.OK {
		t.Fatalf("the job failed on a machine that was only busy: %+v", report.Actions)
	}
	if b.calls != 3 {
		t.Errorf("ran the command %d times, want 3 (two refusals then the real run)", b.calls)
	}
	if b.slept != 2 {
		t.Errorf("waited %d times, want 2 — once after each refusal", b.slept)
	}
}

// Patience has a limit, and the limit has to be said in words a person can act on.
func TestAMachineBusyForEverIsReportedInPlainWords(t *testing.T) {
	b := &busyThenFree{busyFor: 1000}
	declareForTest(t, simpleAction("stuck_action"))

	report := Run(context.Background(), b.deps(), Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "stuck_action"}},
	})

	if report.OK {
		t.Fatal("a machine that never freed the lock was reported as a success")
	}
	if b.calls != busyMaxAttempts {
		t.Errorf("ran the command %d times, want %d", b.calls, busyMaxAttempts)
	}

	whole := reportJSON(t, report)
	said := strings.ToLower(whole)
	for _, want := range []string{"using the package manager", "try again"} {
		if !strings.Contains(said, want) {
			t.Errorf("the report never says %q. It said:\n%s", want, whole)
		}
	}
	// The machine's own words are kept as well, under the plain sentence.
	if !strings.Contains(said, "lock could not be acquired") {
		t.Error("the report threw away what the machine actually said")
	}
}

// reportJSON is the whole report as it would reach the service, which is where a
// message a person reads has to actually appear.
func reportJSON(t *testing.T, r Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("could not marshal the report: %v", err)
	}
	return string(b)
}

// Only the lock is waited out. Anything else is a real failure and must stop at once.
func TestARealFailureIsNotRetried(t *testing.T) {
	f := &fakeExec{fails: map[privexec.ID]error{privexec.SystemdDefaultTarget: errBusy{}}}
	deps := testDeps(f)
	slept := 0
	deps.Sleep = func(context.Context, time.Duration) error { slept++; return nil }
	declareForTest(t, simpleAction("broken_action"))

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "broken_action"}},
	})

	if report.OK {
		t.Fatal("a real failure was reported as a success")
	}
	if slept != 0 {
		t.Errorf("waited %d times for a failure that was not the lock", slept)
	}
}

func TestTheWordsEveryPackageManagerUsesAreRecognised(t *testing.T) {
	for _, said := range []string{
		"Lock could not be acquired (another package manager running?)",
		"Cache lock can not be acquired, exiting",
		"E: Could not get lock /var/lib/dpkg/lock-frontend",
		"Unable to acquire the dpkg frontend lock",
		"E: Unable to lock the administration directory",
		"Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend",
		"Another app is currently holding the yum lock",
		"Waiting for process with pid 4242 to finish",
	} {
		if !packageManagerBusy(CommandRun{Stderr: said}) {
			t.Errorf("not recognised as busy: %q", said)
		}
	}
}

func TestARealErrorIsNotMistakenForTheLock(t *testing.T) {
	for _, said := range []string{
		"E: Unable to locate package ntp",
		"dpkg: error processing package mysql-server-5.5",
		"Permission denied",
		"",
	} {
		if packageManagerBusy(CommandRun{Stderr: said}) {
			t.Errorf("wrongly treated as busy: %q", said)
		}
	}
}

// A cancelled job must not sit waiting for the lock.
func TestWaitingStopsWhenTheJobIsCalledOff(t *testing.T) {
	b := &busyThenFree{busyFor: 1000}
	deps := b.deps()
	deps.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	declareForTest(t, simpleAction("cancelled_action"))

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "cancelled_action"}},
	})

	if report.OK {
		t.Fatal("reported success after being called off")
	}
	if b.calls != 1 {
		t.Errorf("ran the command %d times, want 1 — it was called off during the first wait", b.calls)
	}
}
