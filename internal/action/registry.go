//go:build linux

package action

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// catalog is every action the agent will carry out. Nothing outside it can run.
var catalog = map[string]Action{}

// declare adds an action to the catalog.
//
// It panics on a malformed action. Every rule checkAction enforces is a rule
// whose breach would only show up on a customer's server — an action with no
// preview, a rollback that cannot roll back, a step naming a command the sudo
// grant does not cover. Startup is the right place for that to be noticed.
func declare(a Action) {
	if _, exists := catalog[a.Type]; exists {
		panic("action: duplicate action type " + a.Type)
	}
	if err := checkAction(a); err != nil {
		panic("action: " + err.Error())
	}
	catalog[a.Type] = a
}

// Lookup returns the declared action, or false if the catalog does not have it.
func Lookup(actionType string) (Action, bool) {
	a, ok := catalog[actionType]
	return a, ok
}

// All returns every declared action, in a stable order.
//
// It is what `ghostpsy actions` prints, so a sysadmin can read the whole list of
// what this agent is able to do before deciding to trust it.
func All() []Action {
	types := make([]string, 0, len(catalog))
	for t := range catalog {
		types = append(types, t)
	}
	sort.Strings(types)

	out := make([]Action, 0, len(types))
	for _, t := range types {
		out = append(out, catalog[t])
	}
	return out
}

// checkAction enforces the rules an action must satisfy to exist at all.
func checkAction(a Action) error {
	if a.Type == "" || a.Summary == "" {
		return fmt.Errorf("action %q needs a type and a summary a person can read", a.Type)
	}
	switch a.Reversibility {
	case ReverseFull, ReversePartial, ReverseNone:
	default:
		return fmt.Errorf("action %q must say how reversible it is", a.Type)
	}
	if a.UndoWhy == "" {
		return fmt.Errorf("action %q must explain its undo in plain words", a.Type)
	}
	if len(a.Variants) == 0 {
		return fmt.Errorf("action %q declares no way of being carried out", a.Type)
	}
	if err := checkParams(a); err != nil {
		return err
	}
	for i, v := range a.Variants {
		if err := checkVariant(a, i, v); err != nil {
			return err
		}
	}
	return nil
}

func checkParams(a Action) error {
	for _, p := range a.Params {
		if p.Allow == nil {
			return fmt.Errorf("action %q parameter %q declares no allowed shape", a.Type, p.Name)
		}
		pattern := p.Allow.String()
		if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
			return fmt.Errorf("action %q parameter %q is not anchored with ^ and $", a.Type, p.Name)
		}
	}
	return nil
}

func checkVariant(a Action, index int, v Variant) error {
	// A dry run is required for every action, with no exception. When nothing can
	// be undone the preview is the only safety net there is.
	if len(v.DryRun) == 0 {
		return fmt.Errorf("action %q variant %d has no dry run", a.Type, index)
	}
	if len(v.Run) == 0 {
		return fmt.Errorf("action %q variant %d does nothing", a.Type, index)
	}
	if v.Backup.Kind == BackupArchiveFreed && v.Backup.Freed == nil {
		return fmt.Errorf("action %q variant %d archives what it frees but cannot measure it",
			a.Type, index)
	}
	if a.Reversibility == ReverseNone && len(v.Undo) > 0 {
		return fmt.Errorf(
			"action %q says it cannot be undone but declares an undo step", a.Type)
	}
	if a.Reversibility != ReverseNone && len(v.Undo) == 0 {
		return fmt.Errorf(
			"action %q says it can be undone but declares no way of undoing it", a.Type)
	}

	for _, phase := range [][]Step{v.DryRun, v.Run, v.Verify, v.Undo} {
		for _, step := range phase {
			if err := checkStep(a, step); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkStep(a Action, step Step) error {
	if step.Why == "" {
		return fmt.Errorf("action %q has a step that does not say what it is for", a.Type)
	}
	if (step.Command == "") == (step.Check == "") {
		return fmt.Errorf("action %q step %q must name exactly one command or one check",
			a.Type, step.Why)
	}
	if err := checkStepArgs(a, step); err != nil {
		return err
	}
	if step.Check != "" {
		if !checks[step.Check] {
			return fmt.Errorf("action %q step %q names an unknown check %q",
				a.Type, step.Why, step.Check)
		}
		return checkStepSubject(a, step)
	}
	return checkStepCommand(a, step)
}

// checkStepArgs rejects an argument naming a parameter the action does not have.
//
// It covers check steps as well as command steps now. It used to run only for commands,
// because only commands took arguments — a check read the action's parameters by name
// and could not be told what to look at.
func checkStepArgs(a Action, step Step) error {
	for name := range step.Args {
		if value := step.Args[name]; isParamRef(value) && !declaresParam(a, refName(value)) {
			return fmt.Errorf("action %q step %q refers to parameter %q, which the action does not declare",
				a.Type, step.Why, refName(value))
		}
	}
	return nil
}

// checkStepSubject rejects a check whose setting or value is written out in the
// catalogue and is wrong.
//
// Those two are literal text, so a typo compiles. It would then reach a customer's
// server and refuse the fix there, reporting a mistake of ours as a problem with their
// machine. A parameter reference is not checked here: its value arrives with the
// request and is judged when the check runs.
func checkStepSubject(a Action, step Step) error {
	key, value := step.Args["setting"], step.Args["value"]
	if key == "" || isParamRef(key) || isParamRef(value) {
		return nil
	}
	if _, err := confedit.Check(key, value); err != nil {
		return fmt.Errorf("action %q step %q names setting %q with value %q: %w",
			a.Type, step.Why, key, value, err)
	}
	return nil
}

func declaresParam(a Action, name string) bool {
	for _, p := range a.Params {
		if p.Name == name {
			return true
		}
	}
	return false
}
