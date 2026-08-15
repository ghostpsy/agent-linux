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
	"os/exec"
)

// ID names a declared command. Collectors reference commands by ID, never by
// building an argument list of their own.
type ID string

// ErrNotDeclared is returned when a caller asks for an ID the registry does not
// know. It is the package's whole reason to exist.
var ErrNotDeclared = errors.New("privexec: command is not declared")

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

	cmd := exec.CommandContext(ctx, declared.Binary, declared.Args...)
	// Always explicit, never inherited: sudo resets the environment, so a
	// command must behave the same whether we reached it directly as root or
	// through sudo as the ghostpsy user.
	cmd.Env = declared.Env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}
