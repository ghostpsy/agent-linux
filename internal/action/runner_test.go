//go:build linux

package action

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// declareForTest puts an action in the catalog for one test only.
func declareForTest(t *testing.T, a Action) {
	t.Helper()
	if _, exists := catalog[a.Type]; exists {
		t.Fatalf("test action %q collides with a real one", a.Type)
	}
	catalog[a.Type] = a
	t.Cleanup(func() { delete(catalog, a.Type) })
}

// fakeExec answers every command from a script, and records what it was asked.
type fakeExec struct {
	answers map[privexec.ID]privexec.Result
	fails   map[privexec.ID]error
	ran     []privexec.ID
}

func (f *fakeExec) run(_ context.Context, id privexec.ID, _ privexec.Values) (privexec.Result, error) {
	f.ran = append(f.ran, id)
	if err, bad := f.fails[id]; bad {
		return privexec.Result{ExitCode: 7, Stderr: []byte("it did not work")}, err
	}
	res, known := f.answers[id]
	if !known {
		return privexec.Result{ExitCode: 0}, nil
	}
	return res, nil
}

func testDeps(f *fakeExec) Deps {
	return Deps{
		Exec:         f.run,
		Installed:    func(string) bool { return true },
		FreeBytes:    func(string) (int64, error) { return 100 << 30, nil },
		SwitchedOff:  func() (bool, string) { return false, "" },
		InboundPorts: func() ([]int, error) { return nil, nil },
		Listening:    func(int) bool { return true },
		Protected:    func() ([]string, error) { return nil, nil },
		Sleep:        func(context.Context, time.Duration) error { return nil },
	}
}

// A tiny action wired to two commands that exist on every Linux host.
func simpleAction(typ string) Action {
	return Action{
		Type:          typ,
		Summary:       "do a harmless thing",
		Reversibility: ReverseFull,
		UndoWhy:       "the old value is written down first",
		Variants: []Variant{{
			DryRun: []Step{{Why: "show what would change", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "change it", Command: privexec.SystemdDefaultTarget}},
			Verify: []Step{{Why: "check it worked", Command: privexec.SystemdDefaultTarget}},
			Undo:   []Step{{Why: "put it back", Command: privexec.SystemdDefaultTarget}},
		}},
	}
}

// The rule the whole package exists for. Nothing outside the catalog can run.
func TestRunRefusesAnActionTypeThatIsNotInTheCatalog(t *testing.T) {
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "delete_everything"}},
	})

	if report.OK {
		t.Fatal("expected an unknown action type to be refused")
	}
	if !strings.Contains(report.Actions[0].Refused, "delete_everything") {
		t.Fatalf("expected the refusal to name the action, got %q", report.Actions[0].Refused)
	}
	if len(f.ran) != 0 {
		t.Fatalf("expected nothing at all to run, but these did: %v", f.ran)
	}
}

// The parameters come from the cloud, so they are the one part of an action a
// hostile input could try to steer.
func TestRunRefusesAHostileParameter(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_param",
		Summary:       "act on {unit}",
		Params:        []Param{{Name: "unit", Allow: regexp.MustCompile(`^[a-z]+$`)}},
		Reversibility: ReverseNone,
		Variants: []Variant{{
			Run: []Step{{
				Why:     "act",
				Command: privexec.SystemdFailedUnits,
				Args:    map[string]string{},
			}},
		}},
	})

	hostile := []string{"nginx; rm -rf /", "../../etc/shadow", "$(id)", "nginx\nreboot", ""}
	for _, value := range hostile {
		f := &fakeExec{}
		report := Run(context.Background(), testDeps(f), Job{
			Mode:    ModeRun,
			Actions: []Request{{Type: "test_param", Params: map[string]string{"unit": value}}},
		})

		if report.OK {
			t.Fatalf("expected %q to be refused", value)
		}
		if len(f.ran) != 0 {
			t.Fatalf("expected %q to run nothing, but these ran: %v", value, f.ran)
		}
	}
}

// An unknown parameter name is refused too. A caller that thinks it set
// something must not be allowed to be wrong about it.
func TestRunRefusesAParameterTheActionDoesNotDeclare(t *testing.T) {
	declareForTest(t, simpleAction("test_no_params"))
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "test_no_params", Params: map[string]string{"unit": "nginx"}}},
	})

	if report.OK {
		t.Fatal("expected an undeclared parameter to be refused")
	}
}

// A dry run may only use the steps declared for a dry run. If it could reach the
// real ones, the preview a human approves would be a lie.
func TestDryRunOnlyRunsTheDryRunSteps(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_phases",
		Summary:       "two different phases",
		Reversibility: ReverseNone,
		Variants: []Variant{{
			DryRun: []Step{{Why: "preview", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "for real", Command: privexec.SystemdFailedUnits}},
		}},
	})
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeDryRun, Actions: []Request{{Type: "test_phases"}},
	})

	if !report.OK {
		t.Fatalf("expected the dry run to succeed, got %q", report.Actions[0].Refused)
	}
	for _, id := range f.ran {
		if id == privexec.SystemdFailedUnits {
			t.Fatal("the dry run reached a step declared for the real run")
		}
	}
}

// An action with no dry run cannot exist, because the preview is the safety net
// for everything that cannot be undone.
func TestCatalogRefusesAnActionWithNoDryRun(t *testing.T) {
	err := checkAction(Action{
		Type:          "test_no_preview",
		Summary:       "x",
		Reversibility: ReverseNone,
		Variants:      []Variant{{Run: []Step{{Why: "go", Command: privexec.SystemdDefaultTarget}}}},
	})

	if err == nil {
		t.Fatal("expected an action with no dry run to be refused by the catalog")
	}
}

func TestRunCapturesOutputExitCodeAndDuration(t *testing.T) {
	declareForTest(t, simpleAction("test_capture"))
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.SystemdDefaultTarget: {
			Stdout: []byte("out"), Stderr: []byte("err"), ExitCode: 0,
		},
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeDryRun, Actions: []Request{{Type: "test_capture"}},
	})

	cmd := report.Actions[0].Commands[0]
	if cmd.Stdout != "out" || cmd.Stderr != "err" {
		t.Fatalf("expected both streams captured, got stdout=%q stderr=%q", cmd.Stdout, cmd.Stderr)
	}
	if cmd.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", cmd.ExitCode)
	}
	if cmd.Display == "" {
		t.Fatal("expected the command to be shown as a person would type it")
	}
}

// The machine owner has the last word. An approved job from the cloud does not
// override a switch the person in front of the server threw.
func TestRunObeysTheLocalSwitchEvenForAnApprovedJob(t *testing.T) {
	declareForTest(t, simpleAction("test_switch"))
	f := &fakeExec{}
	deps := testDeps(f)
	deps.SwitchedOff = func() (bool, string) {
		return true, "actions are switched off in /etc/ghostpsy/solve.disabled"
	}

	report := Run(context.Background(), deps, Job{
		Mode: ModeRun, Actions: []Request{{Type: "test_switch"}},
	})

	if report.OK {
		t.Fatal("expected a switched-off machine to refuse an approved job")
	}
	if !strings.Contains(report.Refused, "switched off") {
		t.Fatalf("expected the reason to say so plainly, got %q", report.Refused)
	}
	if len(f.ran) != 0 {
		t.Fatalf("expected nothing to run, but these did: %v", f.ran)
	}
}

// The failure the disk actions were designed around: the archive would need more
// room than the disk we are trying to empty has left.
func TestBackupIsSkippedWithAPlainReasonWhenItWouldNotFit(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_tight_disk",
		Summary:       "free some space",
		Reversibility: ReverseNone,
		UndoWhy:       "deleted files cannot be brought back",
		Variants: []Variant{{
			Backup: BackupPlan{
				Kind:   BackupArchiveFreed,
				Target: "/var",
				Freed:  regexp.MustCompile(`would free ([0-9.]+[KMGT])`),
			},
			DryRun: []Step{{Why: "preview", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "clean", Command: privexec.SystemdFailedUnits}},
		}},
	})
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		// The preview, taken on this machine at this moment, is where the size
		// comes from. Nothing older is trusted.
		privexec.SystemdDefaultTarget: {Stdout: []byte("would free 6.0G of archived journals")},
	}}
	deps := testDeps(f)
	deps.FreeBytes = func(string) (int64, error) { return 2 << 30, nil } // 2 GiB free

	report := Run(context.Background(), deps, Job{
		Mode:    ModeRun,
		Backup:  true,
		Actions: []Request{{Type: "test_tight_disk"}},
	})

	if report.Backup.Taken {
		t.Fatal("expected no backup to be written on a disk that cannot hold it")
	}
	if !strings.Contains(report.Backup.Why, "6.0 GB") || !strings.Contains(report.Backup.Why, "2.0 GB") {
		t.Fatalf("expected the reason to give both numbers in plain words, got %q", report.Backup.Why)
	}
	if report.Undo == nil || report.Undo.Ledger[0].CanPutBack {
		t.Fatal("expected the ledger to say this cannot be put back")
	}
	// The whole point: the fix still runs. Refusing the backup must not refuse
	// the work — that would block the very case the action exists for.
	if !report.OK {
		t.Fatalf("expected the fix to run anyway, got %q", report.Actions[0].Refused)
	}
}

// A check that fails is the moment the undo has to work.
func TestAFailedCheckUndoesWhatCanBeUndone(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_undo",
		Summary:       "change a setting",
		Reversibility: ReverseFull,
		UndoWhy:       "the file is copied before editing",
		Variants: []Variant{{
			DryRun: []Step{{Why: "preview", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "change", Command: privexec.SystemdDefaultTarget}},
			Verify: []Step{{Why: "check", Command: privexec.SystemdFailedUnits}},
			Undo:   []Step{{Why: "put it back", Command: privexec.SystemdListTimers}},
		}},
	})
	f := &fakeExec{fails: map[privexec.ID]error{
		privexec.SystemdFailedUnits: errors.New("the check did not pass"),
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeRun, Actions: []Request{{Type: "test_undo"}},
	})

	if report.OK {
		t.Fatal("expected a failed check to fail the job")
	}
	if report.Undo == nil || !report.Undo.Ran {
		t.Fatal("expected the undo to have run")
	}
	if !report.Undo.Ledger[0].PutBack {
		t.Fatalf("expected the change to be reported as put back, got %q", report.Undo.Ledger[0].Why)
	}
	if !ranCommand(f, privexec.SystemdListTimers) {
		t.Fatal("expected the declared undo step to have run")
	}
}

// An action that cannot be undone must be reported honestly, not smoothed over.
func TestAFailedCheckReportsHonestlyWhenThereIsNoUndo(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_no_undo",
		Summary:       "delete some logs",
		Reversibility: ReverseNone,
		UndoWhy:       "deleted logs are gone",
		Variants: []Variant{{
			DryRun: []Step{{Why: "preview", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "delete", Command: privexec.SystemdDefaultTarget}},
			Verify: []Step{{Why: "check", Command: privexec.SystemdFailedUnits}},
		}},
	})
	f := &fakeExec{fails: map[privexec.ID]error{
		privexec.SystemdFailedUnits: errors.New("the check did not pass"),
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeRun, Actions: []Request{{Type: "test_no_undo"}},
	})

	if report.Undo == nil {
		t.Fatal("expected a ledger even when nothing can be undone")
	}
	if report.Undo.Ledger[0].PutBack {
		t.Fatal("expected the ledger to say this could not be put back")
	}
	if !strings.Contains(report.Undo.Ledger[0].Why, "gone") {
		t.Fatalf("expected the honest reason, got %q", report.Undo.Ledger[0].Why)
	}
}

// An action declares no undo step at all when it has nothing to put back, and an
// undo step it never declared must never be invented.
func TestNoUndoStepIsInventedForAnIrreversibleAction(t *testing.T) {
	err := checkAction(Action{
		Type:          "test_lying",
		Summary:       "x",
		Reversibility: ReverseNone,
		Variants: []Variant{{
			DryRun: []Step{{Why: "p", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "r", Command: privexec.SystemdDefaultTarget}},
			Undo:   []Step{{Why: "u", Command: privexec.SystemdDefaultTarget}},
		}},
	})

	if err == nil {
		t.Fatal("an action that says it cannot be undone must not declare an undo step")
	}
}

// The same preview twice is the same preview. A different one is a different one:
// that is what makes an old approval detectably old.
func TestPreviewIDChangesWhenThePreviewChanges(t *testing.T) {
	declareForTest(t, simpleAction("test_preview_id"))
	job := Job{Mode: ModeDryRun, Actions: []Request{{Type: "test_preview_id"}}}

	first := Run(context.Background(), testDeps(&fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.SystemdDefaultTarget: {Stdout: []byte("would free 4.2G")},
	}}), job)
	same := Run(context.Background(), testDeps(&fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.SystemdDefaultTarget: {Stdout: []byte("would free 4.2G")},
	}}), job)
	changed := Run(context.Background(), testDeps(&fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.SystemdDefaultTarget: {Stdout: []byte("would free 9.9G")},
	}}), job)

	if first.PreviewID == "" {
		t.Fatal("expected a dry run to produce a preview id")
	}
	if first.PreviewID != same.PreviewID {
		t.Fatal("expected the same preview to keep the same id")
	}
	if first.PreviewID == changed.PreviewID {
		t.Fatal("expected a changed preview to get a new id, so an old approval goes stale")
	}
}

// A real run does not produce a preview id: there is nothing left to approve.
func TestARealRunHasNoPreviewID(t *testing.T) {
	declareForTest(t, simpleAction("test_run_no_preview_id"))

	report := Run(context.Background(), testDeps(&fakeExec{}), Job{
		Mode: ModeRun, Actions: []Request{{Type: "test_run_no_preview_id"}},
	})

	if report.PreviewID != "" {
		t.Fatalf("expected no preview id on a real run, got %q", report.PreviewID)
	}
}

// A machine without the tool an action needs is told so, rather than being given
// a command that cannot work.
func TestRunRefusesWhenNoVariantFitsThisMachine(t *testing.T) {
	declareForTest(t, Action{
		Type:          "test_variant",
		Summary:       "needs a tool this host does not have",
		Reversibility: ReverseFull,
		UndoWhy:       "x",
		Variants: []Variant{{
			Needs:  "ufw",
			DryRun: []Step{{Why: "p", Command: privexec.SystemdDefaultTarget}},
			Run:    []Step{{Why: "r", Command: privexec.SystemdDefaultTarget}},
			Undo:   []Step{{Why: "u", Command: privexec.SystemdDefaultTarget}},
		}},
	})
	f := &fakeExec{}
	deps := testDeps(f)
	deps.Installed = func(string) bool { return false }

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun, Actions: []Request{{Type: "test_variant"}},
	})

	if report.OK {
		t.Fatal("expected the action to be refused on a machine that cannot carry it out")
	}
	if !strings.Contains(report.Actions[0].Refused, "ufw") {
		t.Fatalf("expected the refusal to name the missing tool, got %q", report.Actions[0].Refused)
	}
}

// A step whose command was never declared to privexec is a programming error,
// and it must surface at startup rather than half way through a fix.
func TestCatalogRefusesAStepWhoseCommandIsNotDeclared(t *testing.T) {
	err := checkAction(Action{
		Type:          "test_undeclared_step",
		Summary:       "x",
		Reversibility: ReverseNone,
		Variants: []Variant{{
			DryRun: []Step{{Why: "p", Command: privexec.ID("nothing.declares.this")}},
			Run:    []Step{{Why: "r", Command: privexec.ID("nothing.declares.this")}},
		}},
	})

	if err == nil {
		t.Fatal("expected a step naming an undeclared command to be refused")
	}
}

// Every real action in the shipped catalog has to satisfy the same rules.
func TestEveryShippedActionIsWellFormed(t *testing.T) {
	for _, a := range All() {
		if err := checkAction(a); err != nil {
			t.Errorf("action %q: %v", a.Type, err)
		}
	}
}

func ranCommand(f *fakeExec, id privexec.ID) bool {
	for _, ran := range f.ran {
		if ran == id {
			return true
		}
	}
	return false
}

// exitError is what a real failing command produces, so the runner has to read
// an exit code out of one.
var _ = exec.ExitError{}
