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
)

// sudoPath is pinned rather than looked up on PATH: this is the one place the
// agent escalates privilege, and it must not be redirectable by an environment
// a caller controls.
const sudoPath = "/usr/bin/sudo"

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
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Command is one declared privileged command.
type Command struct {
	Binary string
	Args   []string

	// Why says, in plain words, what this command is for. It is printed as a
	// comment above the grant, because a privilege file a sysadmin cannot read
	// is not the promise we made.
	Why string

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

// Run executes the declared command named by id.
func Run(ctx context.Context, id ID) (Result, error) {
	declared, ok := registry[id]
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrNotDeclared, id)
	}

	// Resolve the same way the grant file does, so the path sudo is asked for
	// is exactly the path the rule pins.
	path, err := resolve(declared.Binary)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrNotInstalled, declared.Binary)
	}

	bin, args := invocation(path, declared, os.Geteuid() == 0)
	cmd := exec.CommandContext(ctx, bin, args...)
	// Always explicit, never inherited: sudo resets the environment, so a
	// command must behave the same whether we reached it directly as root or
	// through sudo as the ghostpsy user.
	cmd.Env = declared.Env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, runErr
}

// invocation builds the real command line for a declared command. As root it is
// run directly; otherwise it goes through sudo, which is the only way an
// unprivileged agent can read what it needs.
//
// sudo -n never prompts: if the grant is missing the command fails immediately
// instead of hanging a scan on a password prompt nobody will ever see.
func invocation(path string, c Command, amRoot bool) (string, []string) {
	if amRoot {
		return path, c.Args
	}
	args := make([]string, 0, len(c.Args)+2)
	args = append(args, "-n", path)
	args = append(args, c.Args...)
	return sudoPath, args
}
