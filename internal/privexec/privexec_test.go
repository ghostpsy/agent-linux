//go:build linux

package privexec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// declareForTest adds a command to the registry for one test only.
func declareForTest(t *testing.T, id ID, c Command) {
	t.Helper()
	if _, exists := registry[id]; exists {
		t.Fatalf("test id %q collides with a real declared command", id)
	}
	registry[id] = c
	t.Cleanup(func() { delete(registry, id) })
}

// The security property this whole package exists for: if a command is not
// declared in the registry, the agent must not be able to run it as root.
func TestRunRefusesUndeclaredID(t *testing.T) {
	_, err := Run(context.Background(), ID("definitely-not-declared"))

	if err == nil {
		t.Fatal("expected Run to refuse an undeclared command ID, got nil error")
	}
	if !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("expected ErrNotDeclared, got: %v", err)
	}
}

func TestRunExecutesADeclaredCommandAndCapturesStdout(t *testing.T) {
	declareForTest(t, ID("test:echo"), Command{Binary: "/bin/echo", Args: []string{"hello"}})

	res, err := Run(context.Background(), ID("test:echo"))

	if err != nil {
		t.Fatalf("expected the declared command to run, got error: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello" {
		t.Fatalf("expected stdout %q, got %q", "hello", got)
	}
}

// Two collectors force LC_ALL=C so the command answers in a language their
// parser understands (see internal/collect/network/services.go). sudo deletes
// the environment by default, so a declared command must carry its own or the
// parsing breaks silently on any server that is not set to English.
func TestRunAppliesTheDeclaredEnvironment(t *testing.T) {
	declareForTest(t, ID("test:env"), Command{
		Binary: "/usr/bin/env",
		Env:    []string{"LC_ALL=C"},
	})

	res, err := Run(context.Background(), ID("test:env"))

	if err != nil {
		t.Fatalf("expected the declared command to run, got error: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "LC_ALL=C") {
		t.Fatalf("expected the declared environment to reach the command, got: %q", res.Stdout)
	}
}

// The agent runs as the unprivileged ghostpsy user, so a declared command has
// to go through sudo. Without this the whole catalogue is decoration.
func TestInvocationGoesThroughSudoWhenNotRoot(t *testing.T) {
	c := Command{Binary: "/usr/sbin/iptables-save"}

	bin, args := invocation(c.Binary, c.Args, false)

	if bin != sudoPath {
		t.Fatalf("expected the command to be run through %s, got %q", sudoPath, bin)
	}
	if len(args) == 0 || args[0] != "-n" {
		t.Fatalf("expected sudo to be non-interactive (-n), got %v", args)
	}
	if args[len(args)-1] != "/usr/sbin/iptables-save" {
		t.Fatalf("expected the declared binary to be the last argument, got %v", args)
	}
}

// Running as root already, sudo would be pointless indirection and would fail
// on a host where sudo is not installed at all.
func TestInvocationRunsDirectlyWhenAlreadyRoot(t *testing.T) {
	c := Command{Binary: "/usr/sbin/iptables-save", Args: []string{"-t", "filter"}}

	bin, args := invocation(c.Binary, c.Args, true)

	if bin != "/usr/sbin/iptables-save" {
		t.Fatalf("expected a direct call, got %q", bin)
	}
	if len(args) != 2 || args[0] != "-t" {
		t.Fatalf("expected the declared arguments unchanged, got %v", args)
	}
}

// The grant file pins absolute paths. If Run called a bare name instead, the
// two could disagree on a host where the binary is somewhere unusual, and the
// grant would silently not apply. One source, one resolved path.
func TestRunResolvesABareBinaryNameLikeTheGrantDoes(t *testing.T) {
	declareForTest(t, ID("test:bare"), Command{Binary: "echo", Args: []string{"resolved"}, Why: "x"})

	res, err := Run(context.Background(), ID("test:bare"))

	if err != nil {
		t.Fatalf("expected a bare binary name to be resolved and run, got: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "resolved" {
		t.Fatalf("expected %q, got %q", "resolved", got)
	}
}

// A declared command whose binary is not installed must fail with a clear
// error, not with whatever exec says about a missing file.
func TestRunReportsAMissingBinaryPlainly(t *testing.T) {
	declareForTest(t, ID("test:missing"), Command{Binary: "definitely-not-installed", Why: "x"})

	_, err := Run(context.Background(), ID("test:missing"))

	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("expected ErrNotInstalled, got: %v", err)
	}
}

// Found by running it: ufw shells out to sysctl, and with no PATH it failed
// with "problem running sysctl" — but only when the agent was root. Under sudo
// it worked, because sudo supplies secure_path. The two paths must behave the
// same, which is the whole reason the environment is explicit.
func TestRunGivesEveryCommandAPath(t *testing.T) {
	declareForTest(t, ID("test:path"), Command{Binary: "/usr/bin/env", Why: "x"})

	res, err := Run(context.Background(), ID("test:path"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "PATH=") {
		t.Fatalf("a declared command must get a PATH, got: %q", res.Stdout)
	}
}

// A declared environment adds to that baseline rather than replacing it, or
// declaring LC_ALL would silently remove PATH again.
func TestRunKeepsThePathWhenACommandDeclaresItsOwnEnvironment(t *testing.T) {
	declareForTest(t, ID("test:path-env"), Command{
		Binary: "/usr/bin/env", Env: []string{"LC_ALL=C"}, Why: "x",
	})

	res, err := Run(context.Background(), ID("test:path-env"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "PATH=") || !strings.Contains(out, "LC_ALL=C") {
		t.Fatalf("expected both PATH and the declared LC_ALL, got: %q", out)
	}
}

// The agent has to be able to read its own grant, or it can never tell the
// service whether the grant is out of date.
//
// Reading the file directly does not work: it is 0440 root:root, and making it
// group-readable is still refused on an SELinux host — measured on CentOS 6.10,
// where sudo accepted the relabelled file and the agent still could not open it.
// So the grant includes permission to read the grant, through the agent itself.
func TestTheAgentReadsItsOwnGrantWithCat(t *testing.T) {
	declared, ok := registry[GrantFile]
	if !ok {
		t.Fatal("GrantFile is not declared, so sudo_rule_current can never be reported")
	}
	// A standard command, not our binary. A security team auditing this file has
	// to be able to see what runs as root without reading our source; `cat` on
	// one fixed path answers that on sight. There is nothing secret in the file:
	// it is the list of what the agent may do.
	if declared.Binary != "cat" {
		t.Errorf("the grant read must be a command a reviewer can recognise, got %q", declared.Binary)
	}
	if len(declared.Args) != 1 || declared.Args[0] != GrantPath {
		t.Errorf("args: got %v, want one fixed path %q", declared.Args, GrantPath)
	}
	// No wildcard, ever. `cat` with a pattern would hand the agent any file the
	// pattern reaches.
	for _, arg := range declared.Args {
		if strings.ContainsAny(arg, "*?[") {
			t.Errorf("a wildcard in a cat grant reads more than one file: %q", arg)
		}
	}
	if declared.Why == "" {
		t.Error("every grant needs a reason a person can read above it")
	}
}

// A command that never ran must not report the exit code of success.
//
// The bug this was written for, seen on an Ubuntu 14.04 machine that has no
// systemd at all:
//
//	$ sudo systemctl enable --now unattended-upgrades
//	privexec: command is not installed on this host: systemctl
//	exit 0 · 2ms
//
// The step failed, the job was rolled back, and the line a person reads still
// said exit 0. Result{} is returned on every path that stops before the process
// starts, and the zero value of ExitCode is 0 — the one number that means it
// worked.
func TestAResultFromACommandThatNeverRanDoesNotSaySuccess(t *testing.T) {
	declareForTest(t, ID("test:absent"), Command{Binary: "/usr/bin/definitely-not-installed"})

	res, err := Run(context.Background(), ID("test:absent"))

	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("expected ErrNotInstalled, got %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("a command that was never started reports exit 0, which reads as success")
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode: got %d, want -1 — the same as a process with no exit status", res.ExitCode)
	}
}

// A command declared for software this host does not have is not an error.
//
// The bug this was written for, on an Ubuntu 14.04 machine with no systemd. The
// apt action wrote its two drop-in files correctly, then tried to enable a
// systemd unit, failed, and rolled the whole thing back — undoing a change that
// had already worked.
//
// On 14.04 there is nothing to enable. /etc/cron.daily/apt reads APT::Periodic
// twenty-five times and does the work. The two files were the entire fix.
//
// NeedsPath already knows this. It is the same fact that keeps the grant line out
// of the sudoers file. It was simply never asked at run time.
func TestACommandForSoftwareThatIsNotHereDoesNotApply(t *testing.T) {
	declareForTest(t, ID("test:needs-absent"), Command{
		Binary:    "/bin/echo",
		NeedsPath: "/definitely/not/here",
	})
	declareForTest(t, ID("test:needs-present"), Command{
		Binary:    "/bin/echo",
		NeedsPath: "/etc",
	})
	declareForTest(t, ID("test:needs-nothing"), Command{Binary: "/bin/echo"})

	if applies, why := Applies(ID("test:needs-absent")); applies {
		t.Error("a command whose software is absent must not apply here")
	} else if why == "" {
		t.Error("a skipped step has to say why, or the report is a silent gap")
	}
	if applies, _ := Applies(ID("test:needs-present")); !applies {
		t.Error("a command whose path is there must apply")
	}
	if applies, _ := Applies(ID("test:needs-nothing")); !applies {
		t.Error("a command that declares no path applies anywhere")
	}
}
