//go:build linux

package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// A refused action still reports an empty command list, never a missing one.
//
// The bug this was written for. A nil slice in Go marshals to JSON null, so a
// refused action arrived at the browser as "commands": null. The screen flattens
// every action's commands into one list to draw the terminal, and flatMap over a
// null keeps it — so the list held a null and the page crashed on reading its
// `why`. A person who clicked Solve saw a blank screen and a stack trace.
//
// Refused is a normal outcome, not an error. It must not be able to break the
// page that explains it.
func TestARefusedActionReportsNoCommandsRatherThanNull(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	// Nothing installed, so every variant is missing and the action is refused.
	deps.Installed = func(string) bool { return false }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "prohibit-password",
		}}},
	})

	if len(report.Actions) != 1 || report.Actions[0].Refused == "" {
		t.Fatalf("expected one refused action, got %+v", report.Actions)
	}
	if report.Actions[0].Commands == nil {
		t.Error("a refused action must carry an empty command list, not a nil one")
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// The shape the browser actually receives is what matters here.
	if strings.Contains(string(encoded), `"commands":null`) {
		t.Errorf("commands reached the wire as null:\n%s", encoded)
	}
}

// A verify step that could not run must not count as verified.
//
// Skipping a step whose software is absent is right for the work itself: on a
// machine with no systemd, installing the package is the whole fix. It is wrong
// for the check afterwards. "We could not look" and "we looked and it worked" are
// different answers, and reporting the second for the first is exactly the guess
// this codebase refuses everywhere else.
func TestASkippedVerifyStepIsNotTreatedAsProof(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	deps.Installed = func(binary string) bool { return binary == "apt-get" }
	// Everything applies except the check at the end.
	deps.Applies = func(id privexec.ID) (bool, string) {
		if id == privexec.NTPDaemonRunning {
			return false, "this machine has no pgrep"
		}
		return true, ""
	}

	report := Run(context.Background(), deps, Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "ensure_time_sync"}},
	})

	if report.OK {
		t.Errorf("nothing checked that the fix worked, so this must not say it did:\n%s",
			allOutput(report))
	}
}
