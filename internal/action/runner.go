//go:build linux

package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/confedit"
	"github.com/ghostpsy/agent-linux/internal/privexec"
	"github.com/ghostpsy/agent-linux/internal/redact"
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

	// Applies reports whether a declared command has anything to do on this host,
	// and why not when it does not. Injected like Exec, so a test can decide the
	// answer instead of depending on what happens to be installed where the test
	// runs.
	//
	// Nil means everything applies. That keeps every existing caller and test
	// working, and the one place that matters — the real agent — sets it.
	Applies func(privexec.ID) (bool, string)

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

	// Accounts names the people with an account on this machine, so their names can
	// be covered in everything a command printed before any of it is sent.
	Accounts func() ([]string, error)

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

	// people are the account names to cover in whatever the commands print. Read
	// once for the whole job rather than once per command: /etc/passwd does not
	// change while a fix runs, and the report is masked at one point so a new step
	// cannot be added that forgets to.
	people []string
}

func planAll(deps Deps, job Job) ([]plan, []ActionReport) {
	plans := make([]plan, len(job.Actions))
	reports := make([]ActionReport, len(job.Actions))

	// Before anything is planned, because a report that cannot be masked must not be
	// produced at all. Guessing "there are no accounts" would send every name.
	people, err := accountsOf(deps)

	for i, req := range job.Actions {
		reports[i] = ActionReport{Type: req.Type}
		if err != nil {
			reports[i].Refused = "ghostpsy could not read who has an account on this machine, " +
				"so it cannot cover their names in what it reports. It will not send a command's " +
				"output it has not been able to check: " + err.Error()
			continue
		}

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
			reports[i].Commands = emptyCommands()
			continue
		}
		variant, found := pickVariant(deps, a)
		if !found {
			reports[i].Refused = fmt.Sprintf(
				"this machine does not have %s, which is what this fix needs", neededTools(a))
			reports[i].Commands = emptyCommands()
			continue
		}
		plans[i] = plan{action: a, variant: variant, values: req.Params, people: people}
	}
	return plans, reports
}

// accountsOf reads who lives on this machine, and treats a missing reader as a
// failure rather than as an empty list.
//
// A Deps built without one is a wiring mistake, and the consequence of that mistake is
// every account name on the machine being sent. So it is an error with a sentence
// somebody can act on, not a crash and not a silent pass.
func accountsOf(deps Deps) ([]string, error) {
	if deps.Accounts == nil {
		return nil, errors.New("this agent was built without a way to read the account list")
	}
	return deps.Accounts()
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
		report.Actions[i].WouldRun = wouldRun(plans[i])
	}

	report.OK = allOK(report.Actions)
	report.PreviewID = previewID(report.Actions)
	report.Backup = previewBackup(deps, plans, report.Actions, report.Backup.Asked)
	report.Undo = &UndoReport{Ledger: ledgerOf(plans)}
	return report
}

// wouldRun writes out every command the run phase would carry out.
//
// The same rendering the runner uses for a command it really ran, so the line in the
// preview is the line that appears afterwards. A step that resolves to no command on
// this machine says so rather than being left out: a missing line reads as "nothing
// would happen there", which is the opposite of the truth.
//
// Checks are left out. They run inside the agent and change nothing, and listing
// "ghostpsy check …" among the commands would pad the one list that has to be short
// enough to read.
func wouldRun(p plan) []string {
	var lines []string

	for _, step := range p.variant.Run {
		if step.Check != "" {
			continue
		}
		command, err := stepCommand(step, p.values)
		if err != nil {
			lines = append(lines, "(this machine would refuse: "+err.Error()+")")
			continue
		}
		values, err := stepValues(step, p.values)
		if err != nil {
			lines = append(lines, "(this machine would refuse: "+err.Error()+")")
			continue
		}
		lines = append(lines, privexec.Display(command, values))
	}
	return lines
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
		// A check that could not run is not a check that passed.
		//
		// Skipping a step whose software is absent is right for the work itself:
		// on a machine with no systemd, installing the package is the whole fix.
		// It is wrong for the proof afterwards. "We could not look" and "we looked
		// and it worked" are different answers, and reporting the second for the
		// first is the guess this agent refuses everywhere else.
		for _, run := range runs {
			if run.Skipped != "" {
				phase.OK = false
			}
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
// anythingChanged reports whether a step that can change the machine ran.
//
// Commands are recorded one per attempted step, in order, so each one's step is
// found by position. A check makes a judgement and a step marked Reads only
// looks; everything else counts, including a step that ran and failed, because a
// failure can leave a change half made.
func anythingChanged(steps []Step, runs []CommandRun) bool {
	for i, run := range runs {
		if i >= len(steps) {
			break
		}
		if steps[i].Check != "" || steps[i].Reads {
			continue
		}
		if run.Skipped != "" {
			continue
		}
		return true
	}
	return false
}

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
		//
		// "Happened" used to mean "recorded any command at all", and that is not
		// the same thing. A run that read the firewall's state and then stopped at
		// a check had recorded two commands and changed nothing — and the undo
		// switched off a firewall somebody had just correctly switched on.
		if !anythingChanged(p.variant.Run, reports[i].Commands) {
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
		runs = append(runs, hidePersonalData(p.people, run))
		if !ok {
			return runs, false
		}
	}
	return runs, true
}

// hidePersonalData covers account names, keys and addresses in what a command printed.
//
// It runs here, on every run of every step, because this is the single point every
// command's output passes through. Masking at the moment the report is sent instead
// would leave a new report path free to forget.
//
// The checks that read an earlier step's output see the masked text, which is safe
// because no setting ghostpsy writes has a name or an address for a value — there is a
// test in internal/confedit that keeps that true.
func hidePersonalData(people []string, run CommandRun) CommandRun {
	run.Stdout = redact.Text(people, run.Stdout)
	run.Stderr = redact.Text(people, run.Stderr)
	return run
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

	// Asked before running, not after failing. A step whose software is not on
	// this machine is not part of the work here — the two apt drop-ins are the
	// entire fix on a host with no systemd, and failing on the unit that follows
	// them rolled back a change that had already worked.
	if applies, why := stepApplies(deps, command); !applies {
		return CommandRun{
			Why:     step.Why,
			id:      command,
			Display: privexec.Display(command, values),
			Skipped: why,
			// -1, never 0. Nothing ran, so there is no exit status, and 0 is the
			// number that means it worked.
			ExitCode: -1,
		}, true
	}

	return execWaitingOutTheLock(ctx, deps, command, values, step.Why)
}

// execWaitingOutTheLock runs a command, and tries again while the only thing
// wrong is that something else is using the package manager.
//
// Retrying is safe here in a way it would not be for other failures. apt,
// unattended-upgrade and dnf all take the lock before they do any work, so a
// command that was refused the lock changed nothing — there is no half-done
// state to be made worse by running it again.
//
// This is worth doing because the machines that most need a fix are the ones
// most likely to be busy applying one. An `apt upgrade` started by hand made
// enable_automatic_security_updates fail on its very first step, and the whole
// job was thrown away over a machine that was merely occupied.
func execWaitingOutTheLock(
	ctx context.Context,
	deps Deps,
	command privexec.ID,
	values privexec.Values,
	why string,
) (CommandRun, bool) {
	for attempt := 1; ; attempt++ {
		run, ok := execOnce(ctx, deps, command, values, why)
		if ok || !packageManagerBusy(run) {
			return run, ok
		}
		if attempt >= busyMaxAttempts {
			run.Stderr = busyGaveUp(run.Stderr)
			return run, false
		}
		slog.Info("the package manager is busy, waiting to try again",
			"command", command, "attempt", attempt, "of", busyMaxAttempts)
		if !waitBeforeRetry(ctx, deps, busyWait) {
			return run, false
		}
	}
}

func execOnce(
	ctx context.Context,
	deps Deps,
	command privexec.ID,
	values privexec.Values,
	why string,
) (CommandRun, bool) {
	stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()

	started := time.Now()
	res, runErr := deps.Exec(stepCtx, command, values)
	elapsed := time.Since(started)

	run := CommandRun{
		Why:      why,
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

// stepApplies asks whether this command has anything to do on this machine.
//
// A nil Applies means yes. The check is about the real filesystem, so a test that
// does not care about it must not be made to care: without this, every action test
// would depend on whether the machine running the suite happens to have systemd.
func stepApplies(deps Deps, command privexec.ID) (bool, string) {
	if deps.Applies == nil {
		return true, ""
	}
	return deps.Applies(command)
}

// emptyCommands is a command list with nothing in it, and not a nil one.
//
// The difference only shows up on the wire: nil marshals to null, and the screen
// that draws the terminal flattens every action's commands together. A null in
// that list crashed the page. "Nothing ran" is an answer; null is a gap.
func emptyCommands() []CommandRun { return []CommandRun{} }
