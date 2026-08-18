//go:build linux

// Package privexec is the only way the agent runs a command as root.
//
// Every privileged command is declared in a registry. Run refuses any command
// that is not declared, so "the agent cannot invent a root command" is true by
// construction rather than by discipline. The same registry generates
// /etc/sudoers.d/ghostpsy, so the grant on the host and the agent's behaviour
// cannot drift apart.
package privexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// sudoPath is pinned rather than looked up on PATH: this is the one place the
// agent escalates privilege, and it must not be redirectable by an environment
// a caller controls.
const sudoPath = "/usr/bin/sudo"

// securePath mirrors what sudo hands a command through its own secure_path.
//
// Declared commands get an explicit environment so that running as root and
// running through sudo behave identically. Handing over *no* PATH broke that:
// ufw shells out to sysctl and failed with "problem running sysctl", but only
// on the root path, because sudo was quietly supplying a PATH on the other one.
const securePath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ID names a declared command. Collectors reference commands by ID, never by
// building an argument list of their own.
type ID string

// ErrNotDeclared is returned when a caller asks for an ID the registry does not
// know. It is the package's whole reason to exist.
var ErrNotDeclared = errors.New("privexec: command is not declared")

// ErrNotInstalled means the declared binary is not on this host. It is a normal
// situation — not every server runs nginx — so callers treat it as "no data"
// rather than as a failure.
var ErrNotInstalled = errors.New("privexec: command is not installed on this host")

// Result is the outcome of one declared command.
type Result struct {
	Stdout []byte
	Stderr []byte

	// ExitCode is what the command returned. A scan only ever needed to know
	// whether a command worked, but a fix has to be reported to the person who
	// approved it, and "exit 7" is the part they will paste to a colleague.
	//
	// It is -1 when the command never ran or was killed by a signal.
	ExitCode int
}

// Command is one declared privileged command.
type Command struct {
	Binary string

	// Args is the fixed argument list. An argument may contain a {name}
	// placeholder, which must be matched by an entry in Params — see params.go
	// for why a filled-in value is the most closely checked part of a command.
	Args []string

	// Params declares which values a caller fills in, and the exact shape each
	// one accepts. Empty for every read: those commands are fixed text.
	Params []Param

	// Unprivileged marks a command that needs no privilege at all. It runs
	// directly, never through sudo, and no grant is written for it.
	//
	// A fix needs to check its own work — is the service running, did the
	// setting take — and most of those checks need no privilege. Declaring them
	// here anyway keeps one readable list of everything an action can run;
	// granting them root would break the rule that a shorter grant file is a
	// more trustworthy one.
	Unprivileged bool

	// Why says, in plain words, what this command is for. It is printed as a
	// comment above the grant, because a privilege file a sysadmin cannot read
	// is not the promise we made.
	Why string

	// NeedsPath is a directory or file that must exist on this host for the grant
	// to be written. Empty means the command applies anywhere.
	//
	// The grant file promises it "grants nothing for software you do not have", and
	// checking the binary is not enough to keep that promise. Found on rocky-9: it
	// has no /etc/apt/apt.conf.d, but /usr/bin/install exists on every Linux, so the
	// two apt grants were written on a machine where they can never apply.
	NeedsPath string

	// Env is the environment the command needs to behave predictably, for
	// example LC_ALL=C so its output stays parseable. It must be declared here
	// rather than set at the call site: sudo deletes the environment by
	// default, so the sudoers generator has to emit a matching per-command
	// "Defaults! env_keep" line. A caller cannot know to ask for that.
	Env []string
}

// registry holds every command the agent is allowed to run as root. It is the
// single source of truth: Run consults it, and the sudoers generator prints it.
var registry = map[ID]Command{}

// Declared reports whether id names a command in the registry.
//
// It lets a caller check its own wiring at startup instead of finding out half
// way through a fix on a customer's server that a step names a command the sudo
// grant does not cover.
func Declared(id ID) bool {
	_, ok := registry[id]
	return ok
}

// Run executes the declared command named by id. It takes no parameters, which
// is every command the scan uses.
func Run(ctx context.Context, id ID) (Result, error) {
	return RunWith(ctx, id, nil)
}

// RunWith executes the declared command named by id, filling in the values it
// declared. It refuses an undeclared ID, and refuses a value that does not match
// the shape the command declared for it.
func RunWith(ctx context.Context, id ID, values Values) (Result, error) {
	declared, ok := registry[id]
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrNotDeclared, id)
	}

	filled, err := fill(declared, values)
	if err != nil {
		return Result{}, err
	}

	// Resolve the same way the grant file does, so the path sudo is asked for
	// is exactly the path the rule pins.
	path, err := resolve(declared.Binary)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrNotInstalled, declared.Binary)
	}

	bin, args := invocation(path, filled, declared.Unprivileged || os.Geteuid() == 0)
	cmd := exec.CommandContext(ctx, bin, args...)
	// Always explicit, never inherited: sudo resets the environment, so a
	// command must behave the same whether we reached it directly as root or
	// through sudo as the ghostpsy user. The baseline PATH is part of that —
	// see securePath.
	cmd.Env = append([]string{securePath}, declared.Env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, runErr
}

// Display renders a declared command as a person would type it, so the terminal
// output a customer reads matches what actually ran.
//
// It shows sudo, because that is the truth of it, and it shows the filled-in
// values, because the whole point of showing the command is that the reader can
// check it. It is for reading only: nothing parses this back.
func Display(id ID, values Values) string {
	declared, ok := registry[id]
	if !ok {
		return string(id)
	}
	args, err := fill(declared, values)
	if err != nil {
		args = grantArgs(declared)
	}
	prefix := "sudo "
	if declared.Unprivileged {
		prefix = ""
	}
	return strings.TrimRight(prefix+declared.Binary+" "+strings.Join(args, " "), " ")
}

// invocation builds the real command line for a declared command. As root it is
// run directly; otherwise it goes through sudo, which is the only way an
// unprivileged agent can read what it needs.
//
// sudo -n never prompts: if the grant is missing the command fails immediately
// instead of hanging a scan on a password prompt nobody will ever see.
func invocation(path string, declaredArgs []string, amRoot bool) (string, []string) {
	if amRoot {
		return path, declaredArgs
	}
	args := make([]string, 0, len(declaredArgs)+2)
	args = append(args, "-n", path)
	args = append(args, declaredArgs...)
	return sudoPath, args
}

// AnyDeclaredMatches reports whether any declared command's ID matches pattern.
//
// It lets a caller check at startup that a command chosen from a person's values
// could resolve to something, instead of finding out half way through a fix on a
// customer's server that a template has a typo in it.
func AnyDeclaredMatches(pattern *regexp.Regexp) bool {
	for id := range registry {
		if pattern.MatchString(string(id)) {
			return true
		}
	}
	return false
}
