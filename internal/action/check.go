//go:build linux

package action

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// The judgements no single command can make.
//
// Two of them exist for one failure: turning on a firewall on a remote server is
// how people lose access to a machine for good. The agent is inside the machine,
// so it cannot prove a stranger can still get in. What it can do is exactly what
// a careful sysadmin does — look at the connection it is being reached on, and
// refuse a plan that would cut it.
//
// The third belongs to the machine's owner: a service on their protected list is
// never touched, whatever the cloud says.

func runCheck(ctx context.Context, deps Deps, p plan, step Step, before []CommandRun) (CommandRun, bool) {
	switch step.Check {
	case CheckSomebodyCanStillLogIn:
		return somebodyCanStillLogIn(ctx, deps, p, step.Why)
	case CheckPlanKeepsMeReachable:
		return planKeepsMeReachable(deps, step.Why, before)
	case CheckKeepsMeReachable:
		return keepsMeReachable(deps, step.Why)
	case CheckUnitNotProtected:
		return unitNotProtected(deps, p, step.Why)
	}
	return CommandRun{
		Why:      step.Why,
		Display:  "ghostpsy check " + string(step.Check),
		Stderr:   fmt.Sprintf("%q is not a check this agent knows", step.Check),
		ExitCode: -1,
	}, false
}

// planKeepsMeReachable reads the dry run's own output and refuses a plan that
// would not allow a port somebody is connected on right now.
//
// This runs before anything changes, which is the only place a lock-out can be
// prevented rather than repaired. It works because `ufw --dry-run` prints the
// exact rules it would install: the ports in that text are the ports that would
// still be open.
func planKeepsMeReachable(deps Deps, why string, before []CommandRun) (CommandRun, bool) {
	run := CommandRun{Why: why, Display: "ghostpsy check plan-keeps-me-reachable"}

	ports, err := deps.InboundPorts()
	if err != nil {
		run.Stderr = "ghostpsy could not read which connections are reaching this machine, so it " +
			"will not risk a change that could cut off the way you get in"
		run.ExitCode = -1
		return run, false
	}
	if len(ports) == 0 {
		run.Stdout = "nobody is connected to this machine right now, so there is no session to cut off"
		return run, true
	}
	sort.Ints(ports)

	plan := plannedRules(before)
	if strings.TrimSpace(plan) == "" {
		run.Stderr = "ghostpsy could not read the rules this change would install, so it will not " +
			"switch a firewall on without knowing what it would block"
		run.ExitCode = -1
		return run, false
	}

	var unprotected []int
	for _, port := range ports {
		if !mentionsPort(plan, port) {
			unprotected = append(unprotected, port)
		}
	}

	if len(unprotected) > 0 {
		run.Stderr = fmt.Sprintf(
			"ghostpsy stopped before changing anything. You are connected on %s, and the rules this "+
				"change would install do not mention %s. Switching the firewall on would cut you off "+
				"from this machine.",
			portList(ports), portList(unprotected))
		run.ExitCode = 1
		return run, false
	}

	run.Stdout = fmt.Sprintf("the rules this change would install keep %s open, which is how you "+
		"are connected now", portList(ports))
	return run, true
}

// plannedRules joins the output of the steps that ran before this check.
func plannedRules(before []CommandRun) string {
	var b strings.Builder
	for _, run := range before {
		b.WriteString(run.Stdout)
		b.WriteString("\n")
	}
	return b.String()
}

// mentionsPort reports whether a rule set names this port as a whole number.
//
// Whole number matters: without it, port 22 would be found inside 2222, and the
// check would pass on a machine it was about to cut off.
func mentionsPort(rules string, port int) bool {
	text := strconv.Itoa(port)
	for _, field := range strings.FieldsFunc(rules, isNotDigit) {
		if field == text {
			return true
		}
	}
	return false
}

func isNotDigit(r rune) bool {
	return r < '0' || r > '9'
}

// keepsMeReachable runs after the change and fails if the machine stopped
// answering. Its failing is what triggers the undo.
func keepsMeReachable(deps Deps, why string) (CommandRun, bool) {
	run := CommandRun{Why: why, Display: "ghostpsy check keeps-me-reachable"}

	ports, err := deps.InboundPorts()
	if err != nil {
		run.Stderr = "ghostpsy could not read which connections are reaching this machine, so it " +
			"cannot say whether the way you get in still works. It is putting the change back."
		run.ExitCode = -1
		return run, false
	}
	if len(ports) == 0 {
		run.Stdout = "nobody is connected to this machine right now, so there was no session to cut off"
		return run, true
	}
	sort.Ints(ports)

	var lost []int
	for _, port := range ports {
		if !deps.Listening(port) {
			lost = append(lost, port)
		}
	}

	if len(lost) > 0 {
		run.Stderr = fmt.Sprintf(
			"the way you reach this machine stopped answering: nothing replied on %s after the "+
				"change. ghostpsy is putting it back.", portList(lost))
		run.ExitCode = 1
		return run, false
	}

	run.Stdout = fmt.Sprintf("still reachable: %s answered after the change", portList(ports))
	return run, true
}

// unitNotProtected refuses a service the machine's owner listed as hands off.
func unitNotProtected(deps Deps, p plan, why string) (CommandRun, bool) {
	run := CommandRun{Why: why, Display: "ghostpsy check unit-not-protected"}

	unit := p.values["unit"]
	if unit == "" {
		run.Stderr = "this check needs to know which service, and no service was named"
		run.ExitCode = -1
		return run, false
	}

	protected, err := deps.Protected()
	if err != nil {
		run.Stderr = fmt.Sprintf(
			"ghostpsy could not read the list of services this machine's owner protected, so it "+
				"will not touch %s: %v", unit, err)
		run.ExitCode = -1
		return run, false
	}

	for _, name := range protected {
		if strings.EqualFold(strings.TrimSuffix(name, ".service"),
			strings.TrimSuffix(unit, ".service")) {
			run.Stderr = fmt.Sprintf(
				"%s is on this machine's protected list, so ghostpsy will not touch it. "+
					"Remove it from %s if you want ghostpsy to be allowed to.", unit, ProtectedFileName)
			run.ExitCode = 1
			return run, false
		}
	}

	run.Stdout = fmt.Sprintf("%s is not on this machine's protected list", unit)
	return run, true
}

func portList(ports []int) string {
	text := make([]string, 0, len(ports))
	for _, port := range ports {
		text = append(text, fmt.Sprintf("port %d", port))
	}
	return strings.Join(text, ", ")
}

// somebodyCanStillLogIn refuses a hardening change that would close the last door.
//
// It runs in the dry run, before anything is touched, because this is a failure
// that cannot be repaired afterwards: a machine nobody can log in to cannot be
// fixed by logging in to it. The other reachability checks ask whether the port
// answers, and that question passed on the machine it locked me out of.
func somebodyCanStillLogIn(ctx context.Context, deps Deps, p plan, why string) (CommandRun, bool) {
	run := CommandRun{Why: why, Display: "ghostpsy check somebody-can-still-log-in"}

	// Check, not Lookup: the value is judged here too. A value this setting does
	// not allow has to be refused by the first step, with the real reason, rather
	// than reaching a later step and being reported as "the preview did not work".
	setting, err := confedit.Check(p.values["setting"], p.values["value"])
	if err != nil {
		run.Stderr = err.Error()
		run.ExitCode = 1
		return run, false
	}
	if setting.NeedsAWayIn == confedit.WayInNothing {
		run.Stdout = "this change cannot affect anybody's ability to log in"
		return run, true
	}

	access, accessErr := deps.SSHAccess(ctx)
	if accessErr != nil {
		// Refuse. Not knowing whether anybody can get in is not a reason to close
		// a door — it is the strongest possible reason not to.
		run.Stderr = fmt.Sprintf("ghostpsy could not count how many accounts can log in to this "+
			"server, so it will not turn one of those ways off: %v", accessErr)
		run.ExitCode = -1
		return run, false
	}

	if allowed, missing := access.AllowsChange(setting.NeedsAWayIn); !allowed {
		run.Stderr = "ghostpsy stopped before changing anything. " + missing + "."
		run.ExitCode = 1
		return run, false
	}

	run.Stdout = fmt.Sprintf(
		"%d account(s) on this server can log in with an SSH key, %d of them not root, "+
			"so this change leaves a way in", access.AccountsWithKeys, access.NonRootAccountsWithKeys)
	return run, true
}
