//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/agentconfig"
	"github.com/ghostpsy/agent-linux/internal/state"
)

type fakeSetup struct {
	ran         []string
	visudoFails bool
}

func (f *fakeSetup) run(name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.ran = append(f.ran, call)
	if f.visudoFails && strings.Contains(call, "visudo") {
		return errors.New("parse error near line 3")
	}
	return nil
}

func (f *fakeSetup) did(s string) bool {
	for _, c := range f.ran {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

// The single most dangerous step in the whole install. A malformed file in
// /etc/sudoers.d can lock every administrator out of sudo on the host, so the
// system's own checker runs against a temporary copy first.
func TestSudoRuleIsCheckedByVisudoBeforeItIsInstalled(t *testing.T) {
	f := &fakeSetup{}
	dest := filepath.Join(t.TempDir(), "ghostpsy")

	if err := installSudoRule(dest, "rule\n", f.run); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	if !f.did("visudo -c -f") {
		t.Fatalf("visudo was never run, calls: %v", f.ran)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("the rule was not installed: %v", err)
	}
}

// If the check fails we stop and change nothing. The user's sudo setup must be
// exactly as we found it.
func TestABadSudoRuleIsNeverInstalled(t *testing.T) {
	f := &fakeSetup{visudoFails: true}
	dest := filepath.Join(t.TempDir(), "ghostpsy")

	err := installSudoRule(dest, "this is not valid sudoers\n", f.run)

	if err == nil {
		t.Fatal("expected the install to be refused")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("a rule that failed the check was installed anyway")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("the message should tell the user their sudo setup is untouched, got: %v", err)
	}
}

// Old sudo ignores /etc/sudoers.d entirely unless #includedir is present. A
// grant that looks applied but is never read is worse than no grant, because
// nothing reports it.
func TestSetupRefusesWhenSudoersDoesNotIncludeTheDirectory(t *testing.T) {
	sudoers := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoers, []byte("Defaults env_reset\nroot ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	err := checkSudoersIncludesDropInDir(sudoers)

	if err == nil {
		t.Fatal("expected setup to refuse when #includedir is missing")
	}
	if !strings.Contains(err.Error(), "includedir") {
		t.Errorf("the message should name what is missing, got: %v", err)
	}
}

func TestSetupAcceptsSudoersWithTheIncludeDirective(t *testing.T) {
	sudoers := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoers, []byte("Defaults env_reset\n#includedir /etc/sudoers.d\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	if err := checkSudoersIncludesDropInDir(sudoers); err != nil {
		t.Fatalf("a sudoers file with #includedir must be accepted, got: %v", err)
	}
}

// sudo is the mechanism the whole privilege model stands on. If it is missing
// we install it, because almost every host that lacks it has a working package
// manager — and if that fails we stop rather than fall back to root.
func TestEnsureSudoInstallsItWhenMissing(t *testing.T) {
	f := &fakeSetup{}

	err := ensureSudo(func() bool { return false }, "apt-get", f.run)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.did("apt-get") || !f.did("sudo") {
		t.Fatalf("expected sudo to be installed with apt-get, calls: %v", f.ran)
	}
}

func TestEnsureSudoDoesNothingWhenItIsAlreadyThere(t *testing.T) {
	f := &fakeSetup{}

	if err := ensureSudo(func() bool { return true }, "apt-get", f.run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(f.ran) != 0 {
		t.Fatalf("nothing should have been installed, calls: %v", f.ran)
	}
}

// The honest dead end. There is no root mode, so if sudo cannot be installed
// the message has to say plainly what happened and what to do.
func TestEnsureSudoStopsClearlyWhenItCannotBeInstalled(t *testing.T) {
	failing := func(string, ...string) error { return errors.New("Cannot find a valid baseurl for repo") }

	err := ensureSudo(func() bool { return false }, "yum", failing)

	if err == nil {
		t.Fatal("expected setup to stop")
	}
	for _, want := range []string{"sudo", "install"} {
		if !strings.Contains(strings.ToLower(err.Error()), want) {
			t.Errorf("the message should mention %q, got: %v", want, err)
		}
	}
}

// A host with no known package manager cannot be helped automatically, and
// guessing a command would be worse than saying so.
func TestEnsureSudoSaysSoWithNoKnownPackageManager(t *testing.T) {
	err := ensureSudo(func() bool { return false }, "", func(string, ...string) error { return nil })

	if err == nil {
		t.Fatal("expected setup to stop when it cannot install sudo")
	}
}

// --dry-run must change nothing. It is the promise the "check it first" path in
// the mockup makes to the sysadmin who will not pipe curl into a shell.
func TestDryRunDescribesEveryStepAndRunsNone(t *testing.T) {
	ran := 0
	steps := []setupStep{
		{describe: "Create the locked ghostpsy user", do: func() error { ran++; return nil }},
		{describe: "Install the sudo rule", do: func() error { ran++; return nil }},
	}
	var out strings.Builder

	if err := runSetupSteps(&out, steps, true); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}

	if ran != 0 {
		t.Fatalf("a dry run must not do anything, but %d steps ran", ran)
	}
	for _, want := range []string{"Create the locked ghostpsy user", "Install the sudo rule"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run did not mention %q:\n%s", want, out.String())
		}
	}
}

// A step that fails must stop the install there. Carrying on would leave the
// server half-configured, which is harder to reason about than not installed.
func TestSetupStopsAtTheFirstFailure(t *testing.T) {
	after := 0
	steps := []setupStep{
		{describe: "first", do: func() error { return nil }},
		{describe: "second", do: func() error { return errors.New("no space left on device") }},
		{describe: "third", do: func() error { after++; return nil }},
	}
	var out strings.Builder

	err := runSetupSteps(&out, steps, false)

	if err == nil {
		t.Fatal("expected the failure to stop the install")
	}
	if after != 0 {
		t.Error("steps after a failure must not run")
	}
	if !strings.Contains(err.Error(), "second") {
		t.Errorf("the error should name the step that failed, got: %v", err)
	}
}

// Creating a user that already exists is normal on a re-run, not a failure.
// The installer has to be safe to run twice.
func TestCreateAgentUserIsSafeToRunTwice(t *testing.T) {
	f := &fakeSetup{}

	if err := createAgentUser(func() bool { return true }, f.run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(f.ran) != 0 {
		t.Fatalf("an existing user must not be recreated, calls: %v", f.ran)
	}
}

func TestCreateAgentUserMakesALockedAccount(t *testing.T) {
	f := &fakeSetup{}

	if err := createAgentUser(func() bool { return false }, f.run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	call := strings.Join(f.ran, " ")
	for _, want := range []string{"useradd", "--system", "nologin", agentUser} {
		if !strings.Contains(call, want) {
			t.Errorf("expected the user to be created locked and system-owned, missing %q in: %s", want, call)
		}
	}
}

// The registration step surfaced a raw Go error on a real host:
//
//	"register: post: Post https://... local error: tls: bad record MAC"
//
// That is not a message a busy sysadmin should have to decode.
func TestRegisterFailureIsExplainedInPlainWords(t *testing.T) {
	got := explainRegisterFailure(errors.New(`post: Post "https://api.ghostpsy.com/v1/agent/register": local error: tls: bad record MAC`))

	if !strings.Contains(got.Error(), "could not reach") {
		t.Errorf("expected a plain explanation, got: %v", got)
	}
	if !strings.Contains(got.Error(), "api.ghostpsy.com") {
		t.Errorf("expected the message to name what to check, got: %v", got)
	}
}

// An expired or reused code is the most likely failure, and it needs different
// advice from a network problem — get a new one from the dashboard.
func TestAnInvalidCodeIsExplainedDifferentlyFromANetworkProblem(t *testing.T) {
	got := explainRegisterFailure(errors.New("register: bootstrap token rejected (401)"))

	if !strings.Contains(strings.ToLower(got.Error()), "code") {
		t.Errorf("expected the message to talk about the code, got: %v", got)
	}
	if strings.Contains(got.Error(), "could not reach") {
		t.Errorf("a rejected code is not a network problem, got: %v", got)
	}
}

// The service runs as ghostpsy, but every file the installer creates is written
// by root. Found on a real VM: the agent started, could not read its own
// state.json, exited 1, and systemd restarted it forever. The installer printed
// "This server is now reporting" the whole time.
//
// The token had this exact bug once already. Listing every path in one place is
// what stops it happening a third time.
func TestEveryFileTheAgentNeedsIsHandedToIt(t *testing.T) {
	var chowned []string
	chown := func(path string, _, _ int) error {
		chowned = append(chowned, path)
		return nil
	}

	if err := giveAgentItsFiles(agentOwnedPaths(), 1000, 1000, chown); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{agentconfig.Path(), agentStateDir, state.Path()} {
		if !slices.Contains(chowned, want) {
			t.Errorf("%s is created by root and read by the agent, but was never handed over; got %v", want, chowned)
		}
	}
}

// One unreadable path is the whole failure, so it must stop the install rather
// than let it finish and claim success.
func TestSetupFailsIfAFileCannotBeHandedOver(t *testing.T) {
	chown := func(path string, _, _ int) error {
		if path == state.Path() {
			return errors.New("operation not permitted")
		}
		return nil
	}

	err := giveAgentItsFiles(agentOwnedPaths(), 1000, 1000, chown)

	if err == nil {
		t.Fatal("expected an error when a path could not be handed over")
	}
	if !strings.Contains(err.Error(), state.Path()) {
		t.Errorf("the error must name the path that failed, got: %v", err)
	}
}

// Only a non-default address is written down. Writing the public URL into every
// unit would pin thousands of machines to a value that is meant to be a
// compiled-in default, so moving it later would need every server edited.
func TestTheServiceIsToldTheAddressOnlyWhenItIsNotTheDefault(t *testing.T) {
	if env := serviceEnv(defaultAPIBaseURL); len(env) != 0 {
		t.Errorf("the default address must not be written into the unit, got %v", env)
	}

	env := serviceEnv("http://192.168.64.1:8000")

	if len(env) != 1 || !strings.Contains(env[0], "GHOSTPSY_API_URL=http://192.168.64.1:8000") {
		t.Errorf("a custom address must be carried by the service, got %v", env)
	}
}

// A reply from the server means the server was reached, so blaming the network
// is wrong. Found on a real machine: registration hit the discovery limit and
// the installer told the user to check their firewall.
//
//	could not reach the ghostpsy service to register this machine. Check that
//	this server can make outbound HTTPS connections to api.ghostpsy.com
//	(Response: 403 Forbidden {"detail":"Discovery allows up to three machines..."})
//
// A sysadmin would go and inspect a firewall that was working perfectly.
func TestAServerReplyIsNotReportedAsANetworkProblem(t *testing.T) {
	err := explainRegisterFailure(errors.New(
		`Response: 403 Forbidden {"detail":"Discovery allows up to three machines per organization."}`))

	got := strings.ToLower(err.Error())
	for _, forbidden := range []string{"could not reach", "outbound", "firewall"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the server answered, so the message must not mention %q: %v", forbidden, err)
		}
	}
	if !strings.Contains(got, "refused") && !strings.Contains(got, "declined") {
		t.Errorf("the message should say the service refused the machine, got: %v", err)
	}
}

// The detail from the server is what tells the user which limit they hit, so it
// has to survive into the message.
func TestAServerReplyKeepsWhatTheServerSaid(t *testing.T) {
	err := explainRegisterFailure(errors.New(
		`Response: 403 Forbidden {"detail":"Discovery allows up to three machines per organization."}`))

	if !strings.Contains(err.Error(), "three machines") {
		t.Errorf("the server's own explanation must be kept, got: %v", err)
	}
}

// A genuine network failure has no status code, and must still say so plainly.
func TestATrueNetworkFailureStillBlamesTheNetwork(t *testing.T) {
	err := explainRegisterFailure(errors.New(`post: dial tcp: lookup api.ghostpsy.com: no such host`))

	if !strings.Contains(strings.ToLower(err.Error()), "could not reach") {
		t.Errorf("a lookup failure is a network problem and should say so, got: %v", err)
	}
}
