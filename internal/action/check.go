//go:build linux

package action

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/confedit"
	"github.com/ghostpsy/agent-linux/internal/privexec"
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

// settingOf resolves which setting and value a check is about.
//
// A check step may name its own subject with Args, for an action whose settings are
// fixed rather than asked for: enable_automatic_security_updates sets two named
// settings and takes no parameters at all. Without this a check could only be used by
// an action that happened to have parameters called "setting" and "value" — which is
// how "did the change take effect?" became a question only SSH settings could be asked,
// while apt reported success without checking anything.
//
// Check, not Lookup: the value is judged here too, so a value this setting does not
// allow is refused with the real reason rather than surfacing later as a failed step.
func settingOf(p plan, step Step) (confedit.Setting, string, error) {
	key, value := p.values["setting"], p.values["value"]

	named, err := stepValues(step, p.values)
	if err != nil {
		return confedit.Setting{}, "", err
	}
	if given, ok := named["setting"]; ok {
		key = given
	}
	if given, ok := named["value"]; ok {
		value = given
	}

	setting, err := confedit.Check(key, value)
	return setting, value, err
}

// refuse turns a resolution failure into the step's answer.
//
// The wording lives in one place because three checks share it, and they had already
// begun to drift apart.
func refuse(run CommandRun, err error) (CommandRun, bool) {
	run.Stderr = err.Error()
	run.ExitCode = 1
	return run, false
}

func runCheck(ctx context.Context, deps Deps, p plan, step Step, before []CommandRun) (CommandRun, bool) {
	switch step.Check {
	case CheckSomebodyCanStillLogIn:
		return somebodyCanStillLogIn(ctx, deps, p, step)
	case CheckPlanKeepsMeReachable:
		return planKeepsMeReachable(deps, step.Why, before)
	case CheckKeepsMeReachable:
		return keepsMeReachable(deps, step.Why)
	case CheckUnitNotProtected:
		return unitNotProtected(deps, p, step.Why)
	case CheckServiceIsOneWeConfigure:
		return serviceIsOneWeConfigure(p, step.Why)
	case CheckDropInWillTakeEffect:
		return dropInWillTakeEffect(p, step, before)
	case CheckSettingTookEffect:
		return settingTookEffect(p, step, before)
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
func somebodyCanStillLogIn(ctx context.Context, deps Deps, p plan, step Step) (CommandRun, bool) {
	run := CommandRun{Why: step.Why, Display: "ghostpsy check somebody-can-still-log-in"}

	setting, _, err := settingOf(p, step)
	if err != nil {
		// A change that is dangerous rather than wrong is handed over instead of
		// simply refused — see internal/confedit/danger.go. This is the only check
		// that does so, because it is the first one to run.
		var danger *confedit.DangerousChange
		if errors.As(err, &danger) {
			run.Advice = &DoItYourself{
				Risk:       danger.Risk,
				CheckFirst: danger.CheckFirst,
				Script:     danger.Script(),
			}
		}
		return refuse(run, err)
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

// serviceIsOneWeConfigure refuses a service ghostpsy does not configure, with the
// commands to restart it by hand.
//
// The grant is the source of truth, not a second list: if there is no declared
// command to restart this unit, ghostpsy cannot restart it, and saying so here means
// the answer comes from the preview rather than after somebody approves a plan.
func serviceIsOneWeConfigure(p plan, why string) (CommandRun, bool) {
	unit := p.values["unit"]
	run := CommandRun{Why: why, Display: "ghostpsy check " + string(CheckServiceIsOneWeConfigure)}

	if privexec.Declared(privexec.ServiceRestart(unit)) {
		run.Stdout = fmt.Sprintf("ghostpsy configures %s, so it knows what a restart affects", unit)
		return run, true
	}

	run.Stderr = fmt.Sprintf("ghostpsy does not configure %s, so it will not restart it. "+
		"It restarts only services whose configuration it writes, because it cannot tell what a "+
		"restart of anything else would interrupt", unit)
	run.ExitCode = 1
	run.Advice = &DoItYourself{
		Risk: fmt.Sprintf("restarting %s drops whatever it is doing right now. ghostpsy cannot see "+
			"what that is — requests being served, a job half finished, a connection somebody is using", unit),
		CheckFirst: fmt.Sprintf("read `systemctl status %s` and decide whether an interruption is "+
			"acceptable at this moment", unit),
		Script: strings.Join([]string{
			fmt.Sprintf("sudo systemctl status %s     # read this first", unit),
			fmt.Sprintf("sudo systemctl restart %s", unit),
			fmt.Sprintf("sudo systemctl is-active %s   # confirm it stayed up", unit),
		}, "\n"),
	}
	return run, false
}

// dropInWillTakeEffect refuses a change sshd would read and ignore.
//
// It reads the configuration the previous step printed, rather than reading the file
// itself: that keeps one privileged read in the transcript where the person can see
// the same text this judgement was made from.
func dropInWillTakeEffect(p plan, step Step, before []CommandRun) (CommandRun, bool) {
	run := CommandRun{Why: step.Why, Display: "ghostpsy check " + string(CheckDropInWillTakeEffect)}

	setting, value, err := settingOf(p, step)
	if err != nil {
		// The first step already refused this with the real reason. Repeating the
		// judgement here would report the same problem twice in different words.
		return refuse(run, err)
	}

	mainConfig := outputOf(before, privexec.ReadSSHConfig)
	wins, blocking := confedit.DropInWins(setting, mainConfig)
	if wins {
		run.Stdout = fmt.Sprintf("a file in %s will be read before anything that contradicts it",
			confedit.DropInDirFor(setting))
		return run, true
	}

	run.Stderr = blocking + ". ghostpsy only writes files it created, so it will not change that line"
	run.ExitCode = 1
	run.Advice = &DoItYourself{
		Risk: "editing the main configuration file by hand means a mistake in it stops sshd from " +
			"starting, and a server nobody can log in to cannot be repaired by logging in to it",
		CheckFirst: "run `sudo sshd -t` after the edit and before the reload. If it says anything at " +
			"all, put the copy back rather than reloading",
		Script: strings.Join(confedit.ByHandCommands(setting, value, mainConfig), "\n"),
	}
	return run, false
}

// outputOf returns what a named command printed earlier in this phase.
func outputOf(runs []CommandRun, id privexec.ID) string {
	for _, r := range runs {
		if r.id == id {
			return r.Stdout
		}
	}
	return ""
}

// settingTookEffect reads what the service reported and decides whether the fix worked.
//
// It reads the previous step's output rather than asking again, so the person sees the
// same text this judgement was made from.
func settingTookEffect(p plan, step Step, before []CommandRun) (CommandRun, bool) {
	run := CommandRun{Why: step.Why, Display: "ghostpsy check " + string(CheckSettingTookEffect)}

	setting, value, err := settingOf(p, step)
	if err != nil {
		return refuse(run, err)
	}

	// Which command answers "what are you really running with" is the setting's own
	// business — naming one here would make this check usable for one style only.
	service := confedit.ServiceName(setting)
	effective := outputOf(before, privexec.EffectiveConfig(setting))
	if effective == "" {
		run.Stderr = fmt.Sprintf("%s did not say what it is running with, so there is no way to "+
			"tell whether the change took. Treating that as success would be a guess", service)
		run.ExitCode = 1
		return run, false
	}

	if got, ok := confedit.Effective(setting, value, effective); !ok {
		run.Stderr = fmt.Sprintf("%s asked for %s and %s reports %q",
			setting.Directive, value, service, got)
		run.ExitCode = 1
		return run, false
	}
	run.Stdout = fmt.Sprintf("%s is running with %s %s", service, setting.Directive, value)
	return run, true
}
