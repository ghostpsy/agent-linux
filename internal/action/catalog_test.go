//go:build linux

package action

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/confedit"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// The one failure that would end this product: a fix that locks the operator out
// of their own server. Two tests per action, because there are two moments it can
// be caught — before the change, and after.

// Before. ufw prints the rules it would install, and if the port carrying
// somebody's session is not among them, nothing runs at all.
func TestEnableFirewallStopsBeforeItWouldCutOffTheOperator(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		// The rules ufw would install mention 80 and 443. Not 22.
		privexec.UfwDryRunEnable: {Stdout: []byte(
			"-A ufw-user-input -p tcp --dport 80 -j ACCEPT\n" +
				"-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n")},
	}}
	deps := testDeps(f)
	deps.InboundPorts = func() ([]int, error) { return []int{22}, nil }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "enable_firewall", Params: map[string]string{"ssh_port": "22"}}},
	})

	if report.OK {
		t.Fatal("expected the plan to be refused: it would have cut off port 22")
	}
	if !mentionsInOutput(report, "cut you off") {
		t.Fatalf("expected the reason to say so in plain words, got:\n%s", allOutput(report))
	}
	// A dry run of ufw changes nothing, so this is a refusal to proceed, not a
	// rollback of something already done.
	if ranCommand(f, privexec.UfwEnable) {
		t.Fatal("the firewall was switched on despite the refusal")
	}
}

func TestEnableFirewallAllowsAPlanThatKeepsTheOperatorsPortOpen(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.UfwDryRunAllowPort: {Stdout: []byte(
			"-A ufw-user-input -p tcp --dport 2222 -j ACCEPT\n")},
		privexec.UfwDryRunEnable: {Stdout: []byte(
			"-A ufw-user-input -p tcp --dport 2222 -j ACCEPT\n")},
	}}
	deps := testDeps(f)
	deps.InboundPorts = func() ([]int, error) { return []int{2222}, nil }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "enable_firewall", Params: map[string]string{"ssh_port": "2222"}}},
	})

	if !report.OK {
		t.Fatalf("expected a plan that keeps port 2222 open to be allowed, got:\n%s", allOutput(report))
	}
}

// A rule for 2222 must not be read as covering 22. Getting this wrong passes the
// check on exactly the machine it was written to protect.
func TestTheReachabilityCheckDoesNotMistake2222For22(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.UfwDryRunEnable: {Stdout: []byte("-A ufw-user-input -p tcp --dport 2222 -j ACCEPT\n")},
	}}
	deps := testDeps(f)
	deps.InboundPorts = func() ([]int, error) { return []int{22}, nil }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "enable_firewall", Params: map[string]string{"ssh_port": "22"}}},
	})

	if report.OK {
		t.Fatal("a rule for port 2222 was read as covering port 22")
	}
}

// After. If the machine stops answering anyway, the firewall goes back off
// without waiting to be asked.
func TestEnableFirewallSwitchesItselfBackOffIfTheMachineStopsAnswering(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.UfwDryRunEnable: {Stdout: []byte("-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n")},
	}}
	deps := testDeps(f)
	deps.InboundPorts = func() ([]int, error) { return []int{22}, nil }
	deps.Listening = func(int) bool { return false } // it went quiet

	report := Run(context.Background(), deps, Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "enable_firewall", Params: map[string]string{"ssh_port": "22"}}},
	})

	if report.OK {
		t.Fatal("expected an unreachable machine to fail the job")
	}
	if !ranCommand(f, privexec.UfwDisable) {
		t.Fatal("the firewall was left on with the machine unreachable")
	}
	if report.Undo == nil || !report.Undo.Ran || !report.Undo.Ledger[0].PutBack {
		t.Fatalf("expected the ledger to say the firewall was switched back off, got %+v", report.Undo)
	}
}

// The same failure from the other side: a bad sshd_config leaves a server nobody
// can log into. sshd is asked to check the file before it is asked to read it.
func TestHardenSSHChecksTheConfigBeforeAskingSshdToUseIt(t *testing.T) {
	f := &fakeExec{fails: map[privexec.ID]error{
		privexec.SSHTestConfig: errors.New("bad configuration option"),
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "no",
		}}},
	})

	if report.OK {
		t.Fatal("expected a configuration sshd refuses to fail the job")
	}
	// The only reload allowed here is the one that follows the rollback. A reload
	// before the file was put back would be sshd reading a configuration it had
	// already said no to.
	undo := privexec.RemoveDropIn(mustSetting("ssh.permit_root_login"))
	if ranAfter(f, privexec.ServiceReload("sshd"), undo) {
		t.Fatal("sshd was asked to read a configuration it had already refused")
	}
	// The undo is removing the file ghostpsy added, not restoring a copy of the
	// server's own configuration — that file was never touched.
	if !ranCommand(f, undo) {
		t.Fatalf("the change was left in place after the failure; %v ran", f.ran)
	}
}

func TestHardenSSHPutsTheFileBackIfTheMachineStopsAnswering(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	deps.InboundPorts = func() ([]int, error) { return []int{22}, nil }
	deps.Listening = func(int) bool { return false }

	report := Run(context.Background(), deps, Job{
		Mode: ModeRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "prohibit-password",
		}}},
	})

	if report.OK {
		t.Fatal("expected an unreachable machine to fail the job")
	}
	if !ranCommand(f, privexec.RemoveDropIn(mustSetting("ssh.permit_root_login"))) {
		t.Fatalf("the change was left in place; %v ran", f.ran)
	}
}

// The machine owner's list beats the cloud, and it is checked before anything is
// touched rather than after.
func TestRestartFailedServiceLeavesAProtectedServiceAlone(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	deps.Protected = func() ([]string, error) { return []string{"sshd"}, nil }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "restart_failed_service", Params: map[string]string{"unit": "sshd"}}},
	})

	if report.OK {
		t.Fatal("expected a protected service to be left alone")
	}
	if ranCommand(f, privexec.ServiceRestart("sshd")) {
		t.Fatal("a protected service was restarted")
	}
	if !mentionsInOutput(report, "protected list") {
		t.Fatalf("expected the reason to name the protected list, got:\n%s", allOutput(report))
	}
}

// sshd.service and sshd are the same service. A list that only matches one
// spelling protects nothing.
func TestTheProtectedListIgnoresTheServiceSuffix(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	deps.Protected = func() ([]string, error) { return []string{"sshd.service"}, nil }

	report := Run(context.Background(), deps, Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "restart_failed_service", Params: map[string]string{"unit": "sshd"}}},
	})

	if report.OK || ranCommand(f, privexec.ServiceRestart("sshd")) {
		t.Fatal("expected sshd.service on the list to protect sshd")
	}
}

// The deliberate failure test #183 asks for: the check fails, and the undo has to
// actually work.
func TestARestartThatDoesNotHoldIsStoppedAgain(t *testing.T) {
	f := &fakeExec{fails: map[privexec.ID]error{
		// It came up, then fell over again. is-active reports that.
		privexec.ServiceIsActive: errors.New("inactive"),
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "restart_failed_service", Params: map[string]string{"unit": "sshd"}}},
	})

	if report.OK {
		t.Fatal("expected a service that did not stay up to fail the job")
	}
	if !ranCommand(f, privexec.ServiceStop("sshd")) {
		t.Fatal("expected the service to be stopped again, which is how it was found")
	}
}

// Every shipped fix must say honestly whether it can be undone, and back that up
// with a real rollback. A promise with nothing behind it is the one thing this
// design exists to prevent.
func TestEveryShippedActionThatClaimsAnUndoHasOne(t *testing.T) {
	for _, a := range All() {
		if a.Reversibility == ReverseNone {
			continue
		}
		for i, v := range a.Variants {
			if len(v.Undo) == 0 {
				t.Errorf("action %q variant %d says it can be undone but declares no undo step",
					a.Type, i)
			}
		}
	}
}

// Every command a shipped fix can run has to be in the one registry that also
// writes the sudo grant. Otherwise the file a sysadmin reads is not the truth.
func TestEveryCommandAShippedActionUsesIsDeclaredToPrivexec(t *testing.T) {
	for _, a := range All() {
		for _, v := range a.Variants {
			for _, phase := range [][]Step{v.DryRun, v.Run, v.Verify, v.Undo} {
				for _, step := range phase {
					if step.Command == "" {
						continue
					}
					// checkStepCommand rather than Declared: a command may name the
					// action's parameters, because the grant lists one command per
					// possible change instead of one command with a wildcard.
					if err := checkStepCommand(a, step); err != nil {
						t.Errorf("action %q: %v", a.Type, err)
					}
				}
			}
		}
	}
}

// The best-practice fixes ship first, and this is what stops that decision being
// quietly reversed later. A disk or package action appearing here means somebody
// added it without reading why the order matters.
func TestTheShippedCatalogIsTheFirstFourBestPracticeFixes(t *testing.T) {
	want := []string{
		"enable_automatic_security_updates",
		"enable_firewall",
		"harden_ssh_config",
		"restart_failed_service",
	}

	got := make([]string, 0, len(All()))
	for _, a := range All() {
		got = append(got, a.Type)
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the shipped catalog changed.\nwant %v\ngot  %v\n\n"+
			"Disk cleanup and package updates are deliberately not here yet: a config change "+
			"can be put back byte for byte and deleting logs cannot, so the reversible fixes "+
			"go first. If that is being changed on purpose, change this test with it.", want, got)
	}
}

func allOutput(report Report) string {
	var b strings.Builder
	b.WriteString(report.Refused + "\n")
	for _, a := range report.Actions {
		b.WriteString(a.Refused + "\n")
		for _, c := range a.Commands {
			b.WriteString(c.Stdout + "\n" + c.Stderr + "\n")
		}
	}
	if report.Verify != nil {
		for _, c := range report.Verify.Commands {
			b.WriteString(c.Stdout + "\n" + c.Stderr + "\n")
		}
	}
	return b.String()
}

func mentionsInOutput(report Report, text string) bool {
	return strings.Contains(allOutput(report), text)
}

// ranAfter reports whether first ran before second.
func ranAfter(f *fakeExec, first, second privexec.ID) bool {
	firstAt, secondAt := -1, -1
	for i, id := range f.ran {
		if id == first && firstAt == -1 {
			firstAt = i
		}
		if id == second && secondAt == -1 {
			secondAt = i
		}
	}
	return firstAt != -1 && secondAt != -1 && firstAt < secondAt
}

// The settings confedit can change and the shape harden_ssh_config accepts must
// agree.
//
// They did not: the parameter allowed only letters, and ssh.x11_forwarding has a
// digit in it. A fix the agent was perfectly able to carry out could never be
// asked for, and the refusal blamed the value rather than the pattern. Found by
// trying it against a real machine — the only place the two halves meet.
func TestEverySettingTheAgentCanChangeCanActuallyBeAskedFor(t *testing.T) {
	action, known := Lookup("harden_ssh_config")
	if !known {
		t.Fatal("harden_ssh_config is not in the catalog")
	}

	for _, setting := range confedit.All() {
		if err := checkRequestParams(action, map[string]string{
			"setting": setting.Key,
			"value":   "no",
		}); err != nil {
			// apt settings are not this action's business — it only edits sshd.
			if !strings.HasPrefix(setting.Key, "ssh.") {
				continue
			}
			t.Errorf("%s can be changed but cannot be asked for: %v", setting.Key, err)
		}
	}
}

// The lock-out, as a test. This is the "do not lock yourself out" case #183 asks
// for by name, and it is written from a real failure rather than an imagined one:
// I locked myself out of a Rocky 9 machine with exactly this change.
func TestHardenSSHRefusesToTurnOffTheLastWayIn(t *testing.T) {
	f := &fakeExec{}
	deps := testDeps(f)
	// A cloud image: root has a key, nobody else has one, and nobody has a
	// password worth having. Turning off password logins is fine here; turning off
	// root logins is not.
	deps.SSHAccess = func(context.Context) (confedit.Access, error) {
		return confedit.Access{AccountsWithKeys: 0, NonRootAccountsWithKeys: 0}, nil
	}

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			// prohibit-password keeps key logins, so it is safe — but only if
			// somebody actually has a key. On this machine nobody does.
			"setting": "ssh.permit_root_login", "value": "prohibit-password",
		}}},
	})

	if report.OK {
		t.Fatal("no account has a key, so refusing root passwords leaves no way in")
	}
	if !mentionsInOutput(report, "no way to log in") {
		t.Fatalf("expected the reason to say so plainly, got:\n%s", allOutput(report))
	}
	// The dry run must have stopped before it even described the change: this is a
	// failure that cannot be repaired afterwards.
	if ranConfigCommand(f) {
		t.Fatal("the check has to come first, before anything else is done")
	}
}

// And it must not become a check that refuses everything. A machine with a key
// still gets its hardening.
func TestHardenSSHAllowsTheChangeWhenSomebodyHasAKey(t *testing.T) {
	deps := testDeps(&fakeExec{})
	deps.SSHAccess = func(context.Context) (confedit.Access, error) {
		return confedit.Access{AccountsWithKeys: 1}, nil
	}

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "prohibit-password",
		}}},
	})

	if !report.OK {
		t.Fatalf("expected a machine with a key to be allowed, got:\n%s", allOutput(report))
	}
}

// Not knowing is not permission. Failing to count the accounts must stop the
// change, not wave it through.
func TestHardenSSHRefusesWhenItCannotTellWhoCanLogIn(t *testing.T) {
	deps := testDeps(&fakeExec{})
	deps.SSHAccess = func(context.Context) (confedit.Access, error) {
		return confedit.Access{}, errors.New("could not read /etc/passwd")
	}

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "prohibit-password",
		}}},
	})

	if report.OK {
		t.Fatal("not knowing whether anybody can get in is a reason to stop, not to continue")
	}
}

// A setting that has nothing to do with logging in is not held up by the check.
func TestHardenSSHDoesNotAskAboutLoginsForASettingThatCannotAffectThem(t *testing.T) {
	deps := testDeps(&fakeExec{})
	deps.SSHAccess = func(context.Context) (confedit.Access, error) {
		return confedit.Access{}, errors.New("nobody should be asking")
	}

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.x11_forwarding", "value": "no",
		}}},
	})

	if !report.OK {
		t.Fatalf("X11 forwarding has nothing to do with logging in, got:\n%s", allOutput(report))
	}
}

// A refusal has to say what was actually wrong.
//
// "The preview did not work" is the least useful sentence available, and the step
// that failed already said exactly what the problem was. Found by reading a real
// report from a real machine, where the useful words were buried one level down.
func TestARefusalCarriesTheReasonTheStepGave(t *testing.T) {
	deps := testDeps(&fakeExec{})

	report := Run(context.Background(), deps, Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			// A value this setting does not allow, on purpose.
			"setting": "ssh.permit_root_login", "value": "yes",
		}}},
	})

	if report.OK {
		t.Fatal("expected a value the setting does not allow to be refused")
	}
	refused := report.Actions[0].Refused
	if strings.Contains(refused, "the preview did not work") {
		t.Fatalf("the summary hid the reason: %q", refused)
	}
	if !strings.Contains(refused, "PermitRootLogin") {
		t.Fatalf("expected the real reason in the summary, got %q", refused)
	}
}

// And the value is judged by the first step, before anything describes a change
// that is never going to happen.
func TestAValueTheSettingDoesNotAllowIsRefusedByTheFirstStep(t *testing.T) {
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "yes",
		}}},
	})

	if report.OK {
		t.Fatal("expected the value to be refused")
	}
	if ranConfigCommand(f) {
		t.Fatal("nothing should describe a change that cannot be made")
	}
}

// A dangerous change is refused and handed over, not just refused.
//
// The person still wants it. If the report only says no, they go and do it from
// memory instead — at midnight, without the check that would have saved them. So
// the refusal carries the commands, and the report carries them somewhere the app
// can render as a copy-paste block.
func TestADangerousChangeIsRefusedWithTheCommandsToDoItByHand(t *testing.T) {
	report := Run(context.Background(), testDeps(&fakeExec{}), Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "no",
		}}},
	})

	if report.OK {
		t.Fatal("ghostpsy must never make this change itself")
	}

	advice := report.Actions[0].DoItYourself
	if advice == nil {
		t.Fatal("a dangerous change has to hand over the commands, or the refusal is just unhelpful")
	}
	if advice.Risk == "" || advice.CheckFirst == "" || advice.Script == "" {
		t.Fatalf("the advice is incomplete: %+v", advice)
	}
	if !strings.Contains(advice.Script, "sshd -t") {
		t.Errorf("the commands must check the config before reloading it, got:\n%s", advice.Script)
	}
}

// A refusal that is not a dangerous change carries no advice. Offering "here is
// how to do it yourself" for a value that would weaken the server would be worse
// than saying nothing.
func TestAnOrdinaryRefusalCarriesNoAdvice(t *testing.T) {
	report := Run(context.Background(), testDeps(&fakeExec{}), Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.permit_root_login", "value": "yes",
		}}},
	})

	if report.OK {
		t.Fatal("expected 'yes' to be refused")
	}
	if report.Actions[0].DoItYourself != nil {
		t.Fatal("'yes' opens a door — we do not explain how to do that")
	}
}

// Refusing is not the same as helping.
//
// ghostpsy restarts only services it configures, because it cannot see what nginx is
// serving or what a restart of it interrupts. But somebody whose nginx has failed
// still wants it running, and if all we say is no they will do it from memory without
// looking at the status first. So the refusal carries the commands.
func TestRestartingAServiceWeDoNotConfigureHandsOverTheCommands(t *testing.T) {
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeDryRun,
		Actions: []Request{{Type: "restart_failed_service", Params: map[string]string{"unit": "nginx"}}},
	})

	if report.OK {
		t.Fatal("expected a service ghostpsy does not configure to be refused")
	}
	if len(report.Actions) == 0 || report.Actions[0].DoItYourself == nil {
		t.Fatalf("the refusal carried no way to do it by hand:\n%s", allOutput(report))
	}

	advice := report.Actions[0].DoItYourself
	// The status first. Copying the restart without the look is copying the risk.
	if !strings.Contains(advice.Script, "systemctl status nginx") {
		t.Errorf("the commands do not look at the service first:\n%s", advice.Script)
	}
	if !strings.Contains(advice.Script, "systemctl restart nginx") {
		t.Errorf("the commands do not restart the service:\n%s", advice.Script)
	}
	if advice.Risk == "" || advice.CheckFirst == "" {
		t.Errorf("the advice does not say what the risk is or what to confirm: %+v", advice)
	}
	// And nothing was run.
	if len(f.ran) != 0 {
		t.Errorf("commands ran despite the refusal: %v", f.ran)
	}
}

// The other half of the same rule: a service we do configure is still restarted.
func TestRestartingAServiceWeConfigureStillWorks(t *testing.T) {
	f := &fakeExec{}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "restart_failed_service", Params: map[string]string{"unit": "sshd"}}},
	})

	if !report.OK {
		t.Fatalf("expected sshd to be restartable, got:\n%s", allOutput(report))
	}
	if !ranCommand(f, privexec.ServiceRestart("sshd")) {
		t.Error("sshd was not restarted")
	}
}

// A drop-in that would be read and ignored is the worst outcome available: we write a
// file, report success, and change nothing. So the preview asks the question, and the
// answer comes from the server's own file rather than from an assumption about it.
func TestHardenSSHRefusesWhenADropInWouldBeIgnored(t *testing.T) {
	// A hand-edited server: the setting is above the Include, so sshd reads it first.
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.ReadSSHConfig: {Stdout: []byte(
			"MaxAuthTries 10\nInclude /etc/ssh/sshd_config.d/*.conf\n")},
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeDryRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.max_auth_tries", "value": "5",
		}}},
	})

	if report.OK {
		t.Fatal("expected a change that would be silently ignored to be refused")
	}
	if !mentionsInOutput(report, "line 1") {
		t.Fatalf("the reason does not say which line is in the way:\n%s", allOutput(report))
	}
	if len(report.Actions) == 0 || report.Actions[0].DoItYourself == nil {
		t.Fatalf("the refusal carried no way to do it by hand:\n%s", allOutput(report))
	}
	if !strings.Contains(report.Actions[0].DoItYourself.Script, "sshd -t") {
		t.Errorf("the commands skip the check that makes the edit safe:\n%s",
			report.Actions[0].DoItYourself.Script)
	}
	// Nothing was installed.
	if ranCommand(f, privexec.InstallDropIn(confedit.Change{
		Setting: mustSetting("ssh.max_auth_tries"), Value: "5",
	})) {
		t.Error("the file was installed even though it would have been ignored")
	}
}

// And the normal case: a stock server, where the Include is near the top.
func TestHardenSSHInstallsADropInOnAStockServer(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.ReadSSHConfig: {Stdout: []byte(
			"Include /etc/ssh/sshd_config.d/*.conf\n#MaxAuthTries 6\nX11Forwarding yes\n")},
		privexec.SSHEffectiveConfig: {Stdout: []byte("maxauthtries 5\n")},
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode: ModeRun,
		Actions: []Request{{Type: "harden_ssh_config", Params: map[string]string{
			"setting": "ssh.max_auth_tries", "value": "5",
		}}},
	})

	if !report.OK {
		t.Fatalf("expected a stock server to accept the change, got:\n%s", allOutput(report))
	}
	want := privexec.InstallDropIn(confedit.Change{
		Setting: mustSetting("ssh.max_auth_tries"), Value: "5",
	})
	if !ranCommand(f, want) {
		t.Errorf("the file was not installed; %v ran instead", f.ran)
	}
}

// An action that takes no copy must not say it puts one back.
//
// Both configuration actions still promised "put back byte for byte from the copy taken
// before it was edited" after they stopped taking a copy at all. ghostpsy now installs a
// file of its own beside the distribution's, so the undo is `rm` and there is nothing of
// this server's to keep — a better undo, described by a sentence that had become false.
// It reached the person approving the change, in the report, as a reason to say yes.
func TestNoActionPromisesACopyItDoesNotTake(t *testing.T) {
	copyWords := []string{"copy", "backup", "put back byte for byte"}

	for _, a := range All() {
		for _, v := range a.Variants {
			if v.Backup.Kind != BackupNone {
				continue
			}
			for _, word := range copyWords {
				if strings.Contains(strings.ToLower(a.UndoWhy), word) {
					t.Errorf("%s takes no copy, and its undo says %q:\n\t%s", a.Type, word, a.UndoWhy)
				}
			}
		}
	}
}

// Switching on automatic security updates has to be proved, not assumed.
//
// The verify step ran `apt-config dump` and printed it, and nobody read the output.
// apt-config exits 0 on any machine, and `unattended-upgrade --dry-run` succeeds
// whatever the periodic settings say — so this action reported success without ever
// checking that either setting had taken. The SSH action got a real judgement in the
// same change; this one, which the catalogue calls the highest-value action, did not.
func TestAutomaticUpdatesFailsWhenAptDidNotTakeTheSetting(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		// apt kept the machine's own answer for one of the two.
		privexec.APTEffectiveConfig: {Stdout: []byte(
			"APT::Periodic::Update-Package-Lists \"1\";\n" +
				"APT::Periodic::Unattended-Upgrade \"0\";\n")},
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "enable_automatic_security_updates"}},
	})

	if report.OK {
		t.Fatal("apt reports 0 for a setting we set to 1, so this did not work")
	}
	if !mentionsInOutput(report, "Unattended-Upgrade") {
		t.Errorf("the reason has to name the setting that did not take:\n%s", allOutput(report))
	}
}

// And it must still pass on a machine where both really did take.
func TestAutomaticUpdatesPassesWhenAptTookBothSettings(t *testing.T) {
	f := &fakeExec{answers: map[privexec.ID]privexec.Result{
		privexec.APTEffectiveConfig: {Stdout: []byte(
			"APT::Periodic::Update-Package-Lists \"1\";\n" +
				"APT::Periodic::Unattended-Upgrade \"1\";\n")},
	}}

	report := Run(context.Background(), testDeps(f), Job{
		Mode:    ModeRun,
		Actions: []Request{{Type: "enable_automatic_security_updates"}},
	})

	if !report.OK {
		t.Fatalf("both settings took, so this worked:\n%s", allOutput(report))
	}
}
