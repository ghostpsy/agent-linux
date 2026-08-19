//go:build linux

package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/confedit"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// Deps is everything the runner touches outside itself.
//
// Gathered in one place on purpose: every rule about when and how we change a
// customer's server can then be tested without changing one.
type Deps struct {
	// Exec runs a declared privileged command. Nothing else here can run
	// anything.
	Exec func(context.Context, privexec.ID, privexec.Values) (privexec.Result, error)

	// Installed reports whether a binary exists on this host, which is how a
	// variant is chosen.
	Installed func(binary string) bool

	// FreeBytes reports the space left on the filesystem holding path.
	FreeBytes func(path string) (int64, error)

	// SwitchedOff asks the machine whether its owner has turned actions off, and
	// why. It beats an approved job from the cloud.
	SwitchedOff func() (bool, string)

	// InboundPorts lists the ports of connections somebody is currently using to
	// reach this machine. That is how a firewall change can be stopped before it
	// locks its own operator out.
	InboundPorts func() ([]int, error)

	// Listening reports whether anything is accepting connections on a port.
	Listening func(port int) bool

	// Protected lists the services this machine's owner has said ghostpsy must
	// not touch. Their list beats an approved job.
	Protected func() ([]string, error)

	// SSHAccess counts how many accounts could still log in over SSH. It is what
	// stops a hardening change closing the last door.
	SSHAccess func(context.Context) (confedit.Access, error)

	Sleep func(context.Context, time.Duration) error
}

// Run carries out a job and reports what happened.
//
// It never returns an error. Every failure belongs in the report: the person who
// approved this is waiting to be told what happened on their server, and an error
// swallowed on the way home is the failure this whole product exists to remove.
func Run(ctx context.Context, deps Deps, job Job) Report {
	report := carryOut(ctx, deps, job)

	// Always a list, never null. A switched-off machine plans nothing, and a nil
	// slice becomes JSON null — which the app could not tell from a report with no
	// actions field at all, so it showed the person nothing instead of the reason
	// their machine refused.
	if report.Actions == nil {
		report.Actions = []ActionReport{}
	}

	// Every dry run gets a preview id, including one that refused everything.
	//
	// A refusal is an answer to "what would happen here": nothing, and this is
	// why. The service will not accept a report without an id, so without this
	// the machine cannot deliver its refusal at all — the job sits in "proposed"
	// for ever and the screen tells somebody to wait for something that will
	// never happen. Found on a real machine with no firewall tool installed.
	if job.Mode == ModeDryRun && report.PreviewID == "" {
		report.PreviewID = previewID(report.Actions)
	}
	return report
}

func carryOut(ctx context.Context, deps Deps, job Job) Report {
	report := Report{Mode: job.Mode, Backup: BackupReport{Asked: job.Backup}}

	if off, why := deps.SwitchedOff(); off {
		// The machine owner has the last word, and it beats an approved job.
		report.Refused = why
		report.Backup.Why = "nothing ran, so there was nothing to back up"
		return report
	}
	if len(job.Actions) == 0 {
		report.Refused = "the service sent a job with no actions in it"
		return report
	}

	plans, reports := planAll(deps, job)
	report.Actions = reports
	if anyRefused(reports) {
		// All or nothing. Half a plan is not the plan the person approved, and
		// deciding for them which half to keep is not ours to do.
		report.Backup.Why = "nothing ran, so there was nothing to back up"
		report.Undo = &UndoReport{Ledger: ledgerOf(plans)}
		return report
	}

	if job.Mode == ModeDryRun {
		return dryRun(ctx, deps, plans, report)
	}
	return realRun(ctx, deps, job, plans, report)
}

// plan is one action matched to this machine, with its values already checked.
type plan struct {
	action  Action
	variant Variant
	values  map[string]string
}

func planAll(deps Deps, job Job) ([]plan, []ActionReport) {
	plans := make([]plan, len(job.Actions))
	reports := make([]ActionReport, len(job.Actions))

	for i, req := range job.Actions {
		reports[i] = ActionReport{Type: req.Type}

		a, known := Lookup(req.Type)
		if !known {
			// The first wall, and the reason this package exists.
			reports[i].Refused = fmt.Sprintf(
				"%q is not an action this agent knows how to carry out", req.Type)
			continue
		}
		reports[i].Summary = fillText(a.Summary, req.Params)
		reports[i].Reversibility = a.Reversibility
		reports[i].UndoWhy = a.UndoWhy

		if err := checkRequestParams(a, req.Params); err != nil {
			reports[i].Refused = err.Error()
			continue
		}
		variant, found := pickVariant(deps, a)
		if !found {
			reports[i].Refused = fmt.Sprintf(
				"this machine does not have %s, which is what this fix needs", neededTools(a))
			continue
		}
		plans[i] = plan{action: a, variant: variant, values: req.Params}
	}
	return plans, reports
}

// pickVariant chooses how to carry the action out on this machine.
func pickVariant(deps Deps, a Action) (Variant, bool) {
	for _, v := range a.Variants {
		if v.Needs == "" || deps.Installed(v.Needs) {
			return v, true
		}
	}
	return Variant{}, false
}

func neededTools(a Action) string {
	tools := make([]string, 0, len(a.Variants))
	for _, v := range a.Variants {
		if v.Needs != "" {
			tools = append(tools, v.Needs)
		}
	}
	if len(tools) == 0 {
		return "the tools this fix needs"
	}
	return strings.Join(tools, " or ")
}

// dryRun previews every action and changes nothing.
func dryRun(ctx context.Context, deps Deps, plans []plan, report Report) Report {
	for i := range plans {
		runs, ok := runPhase(ctx, deps, plans[i], plans[i].variant.DryRun)
		report.Actions[i].Commands = runs
		report.Actions[i].OK = ok
		if !ok {
			// The step's own words, not a sentence of ours. "The preview did not
			// work" tells somebody nothing they can act on, and the reason is
			// right there in what failed.
			report.Actions[i].Refused = whyItStopped(runs,
				"the preview did not work, so nothing was changed")
			report.Actions[i].DoItYourself = adviceFrom(runs)
		}
		report.Actions[i].FreedBytes = freedFrom(plans[i], runs)
	}

	report.OK = allOK(report.Actions)
	report.PreviewID = previewID(report.Actions)
	report.Backup = previewBackup(deps, plans, report.Actions, report.Backup.Asked)
	report.Undo = &UndoReport{Ledger: ledgerOf(plans)}
	return report
}

// realRun does the work, checks it, and undoes it if the check fails.
func realRun(ctx context.Context, deps Deps, job Job, plans []plan, report Report) Report {
	// The backup decision is made now, on this machine, from the space it has
	// this minute. Reusing a number from the preview would be assuming the very
	// thing that has to be true.
	report.Backup = decideBackup(ctx, deps, plans, job.Backup, &report)

	for i := range plans {
		runs, ok := runPhase(ctx, deps, plans[i], plans[i].variant.Run)
		report.Actions[i].Commands = append(report.Actions[i].Commands, runs...)
		report.Actions[i].OK = ok
		if !ok {
			report.Actions[i].Refused = whyItStopped(runs,
				"this action failed, so the rest of the plan was stopped")
			markNotReached(report.Actions[i+1:])
			break
		}
	}

	report.OK = allOK(report.Actions)
	if report.OK {
		report.Verify = verify(ctx, deps, plans)
		report.OK = report.Verify.OK
	}

	if report.OK {
		report.Undo = &UndoReport{Ledger: ledgerOf(plans)}
		return report
	}

	// The check failed, or a step did. Put back everything that declared a way
	// to be put back, and say plainly what could not be.
	report.Undo = undo(ctx, deps, plans, report.Actions)
	return report
}

func verify(ctx context.Context, deps Deps, plans []plan) *PhaseReport {
	settle := longestSettle(plans)
	if settle > 0 {
		// A service that started a moment ago is not yet proof of anything.
		_ = deps.Sleep(ctx, settle)
	}

	phase := &PhaseReport{OK: true}
	for i := range plans {
		runs, ok := runPhase(ctx, deps, plans[i], plans[i].variant.Verify)
		phase.Commands = append(phase.Commands, runs...)
		if !ok {
			phase.OK = false
		}
	}
	return phase
}

func longestSettle(plans []plan) time.Duration {
	var longest time.Duration
	for _, p := range plans {
		if p.action.Settle > longest {
			longest = p.action.Settle
		}
	}
	return longest
}

// undo runs each action's declared rollback, newest change first.
//
// Newest first because a later action may depend on an earlier one. Putting them
// back in the order they were made would restore a state the next rollback then
// undoes again.
func undo(ctx context.Context, deps Deps, plans []plan, reports []ActionReport) *UndoReport {
	out := &UndoReport{Ran: true, Ledger: ledgerOf(plans)}
	putBack := map[string]bool{}

	for i := len(plans) - 1; i >= 0; i-- {
		p := plans[i]
		if p.action.Type == "" || len(p.variant.Undo) == 0 {
			continue
		}
		// Only put back something that actually happened. Rolling back an action
		// that never ran would itself be a change nobody asked for.
		if len(reports[i].Commands) == 0 {
			continue
		}
		runs, ok := runPhase(ctx, deps, p, p.variant.Undo)
		out.Commands = append(out.Commands, runs...)
		if !ok {
			slog.Warn("could not put a change back", "action", p.action.Type)
		}
		putBack[p.action.Type] = ok
	}

	for i, entry := range out.Ledger {
		done, tried := putBack[entry.Type]
		if !tried {
			continue
		}
		out.Ledger[i].PutBack = done
		if !done {
			out.Ledger[i].Why = "ghostpsy tried to put this back and could not. " + entry.Why
		}
	}
	return out
}

// ledgerOf builds the honest "what can and cannot be put back" list.
//
// It is produced whether or not anything went wrong, because it is what the
// person needs before they commit — not an apology afterwards.
func ledgerOf(plans []plan) []LedgerEntry {
	ledger := make([]LedgerEntry, 0, len(plans))
	for i := range plans {
		a := plans[i].action
		if a.Type == "" {
			continue
		}
		// Saying it can be undone is not enough. Something has to actually be
		// able to do it, or the promise is empty.
		canPutBack := a.Reversibility != ReverseNone && len(plans[i].variant.Undo) > 0
		ledger = append(ledger, LedgerEntry{
			Type:       a.Type,
			CanPutBack: canPutBack,
			Why:        a.UndoWhy,
		})
	}
	return ledger
}

// runPhase runs the steps of one phase in order and stops at the first failure.
func runPhase(ctx context.Context, deps Deps, p plan, steps []Step) ([]CommandRun, bool) {
	runs := make([]CommandRun, 0, len(steps))

	for _, step := range steps {
		// The steps that ran already are passed on, because one check has to read
		// them: the only way to know a firewall would not cut you off is to read
		// the rules its own dry run just printed.
		run, ok := runStep(ctx, deps, p, step, runs)
		runs = append(runs, run)
		if !ok {
			return runs, false
		}
	}
	return runs, true
}

func runStep(ctx context.Context, deps Deps, p plan, step Step, before []CommandRun) (CommandRun, bool) {
	if step.Check != "" {
		return runCheck(ctx, deps, p, step, before)
	}

	values, err := stepValues(step, p.values)
	if err != nil {
		// Cannot happen for a declared action — checkAction rejects a step that
		// names a parameter the action does not have — so it is reported rather
		// than ignored.
		return CommandRun{Why: step.Why, Stderr: err.Error(), ExitCode: -1}, false
	}

	// Which declared command to run can depend on what was asked for, because the
	// grant lists one command per possible change rather than one command with a
	// wildcard. A combination the grant does not cover stops here, and says so.
	command, err := stepCommand(step, p.values)
	if err != nil {
		return CommandRun{Why: step.Why, Stderr: err.Error(), ExitCode: -1}, false
	}

	stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()

	started := time.Now()
	res, runErr := deps.Exec(stepCtx, command, values)
	elapsed := time.Since(started)

	run := CommandRun{
		Why:      step.Why,
		id:       command,
		Display:  privexec.Display(command, values),
		Stdout:   strings.TrimRight(string(res.Stdout), "\n"),
		Stderr:   strings.TrimRight(string(res.Stderr), "\n"),
		ExitCode: res.ExitCode,
		Millis:   elapsed.Milliseconds(),
	}
	if runErr != nil && run.Stderr == "" {
		run.Stderr = runErr.Error()
	}
	return run, runErr == nil
}

func stepValues(step Step, params map[string]string) (privexec.Values, error) {
	if len(step.Args) == 0 {
		return nil, nil
	}
	values := make(privexec.Values, len(step.Args))
	for name, template := range step.Args {
		if !isParamRef(template) {
			values[name] = template
			continue
		}
		value, given := params[refName(template)]
		if !given {
			return nil, fmt.Errorf("no value was given for %q", refName(template))
		}
		values[name] = value
	}
	return values, nil
}

// whyItStopped is the reason the last step gave, or a fallback.
//
// A summary that says "it did not work" wastes the one place a person looks
// first, when the step that failed already said exactly what was wrong.
func whyItStopped(runs []CommandRun, fallback string) string {
	if len(runs) == 0 {
		return fallback
	}
	last := runs[len(runs)-1]
	if reason := strings.TrimSpace(last.Stderr); reason != "" {
		return reason
	}
	return fallback
}

// adviceFrom lifts a step's hand-it-over advice onto the action.
//
// The app should not have to hunt through a list of commands to find the one thing
// the person needs, so it is carried where they will look.
func adviceFrom(runs []CommandRun) *DoItYourself {
	for _, run := range runs {
		if run.Advice != nil {
			return run.Advice
		}
	}
	return nil
}

// markNotReached says so out loud for the actions after a failure.
//
// Left blank they would look identical to an action that failed, and the person
// reading the report cannot tell "it broke" from "we stopped before it".
func markNotReached(reports []ActionReport) {
	for i := range reports {
		reports[i].Refused = "not reached: an earlier action failed, so this one was left alone"
	}
}

func allOK(reports []ActionReport) bool {
	if len(reports) == 0 {
		return false
	}
	for _, r := range reports {
		if !r.OK {
			return false
		}
	}
	return true
}

func anyRefused(reports []ActionReport) bool {
	for _, r := range reports {
		if r.Refused != "" {
			return true
		}
	}
	return false
}

// previewID identifies a preview by what it says would happen.
//
// Durations are deliberately left out: a preview that says the same thing twice
// is the same preview, and an approval must not go stale because a command took
// a second longer. What the machine would do, and what it reports it would free,
// are in — those changing is exactly when an old approval has to be refused.
func previewID(reports []ActionReport) string {
	h := sha256.New()
	for _, r := range reports {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00", r.Type, r.Summary, r.FreedBytes)
		for _, c := range r.Commands {
			_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00", c.Display, c.Stdout, c.ExitCode)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
