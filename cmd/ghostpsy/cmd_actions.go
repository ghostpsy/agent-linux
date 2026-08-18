//go:build linux

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/action"
	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// newActionsCommand prints everything this agent is able to change.
//
// It exists for the person deciding whether to install us. "It only does what is
// on a fixed list" is a claim, and a claim a sysadmin cannot check is worth
// nothing. This is the list, read out of the same catalog the runner uses, so the
// two cannot disagree.
func newActionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "actions",
		Short: "List every change this agent is able to make",
		Long: "Prints the complete list of fixes this agent can carry out, and for each one " +
			"whether it can be undone.\n\nNothing outside this list can run, whatever the " +
			"service asks for. To stop ghostpsy changing anything at all, create\n" +
			"/etc/ghostpsy/" + action.SwitchFileName + ".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			printActions(cmd.OutOrStdout())
			return nil
		},
	}
}

func printActions(out io.Writer) {
	_, _ = fmt.Fprintf(out, "This agent can make %d kinds of change, and nothing else.\n\n", len(action.All()))

	for _, a := range action.All() {
		_, _ = fmt.Fprintf(out, "%s\n", a.Type)
		_, _ = fmt.Fprintf(out, "  What it does   %s\n", a.Summary)
		_, _ = fmt.Fprintf(out, "  Can be undone  %s — %s\n", undoWords(a.Reversibility), a.UndoWhy)
		if len(a.Params) > 0 {
			for _, p := range a.Params {
				_, _ = fmt.Fprintf(out, "  You choose     %s: %s\n", p.Name, p.Why)
			}
		}
		_, _ = fmt.Fprintln(out)
	}

	_, _ = fmt.Fprintf(out, "It can change these settings in a configuration file, and no others:\n\n")
	for _, s := range confedit.All() {
		_, _ = fmt.Fprintf(out, "%s\n", s.Key)
		_, _ = fmt.Fprintf(out, "  Sets           %s in %s\n", s.Directive, s.File)
		_, _ = fmt.Fprintf(out, "  Allowed values %s\n", s.Allow.String())
		_, _ = fmt.Fprintf(out, "  Why it is safe %s\n\n", s.Why)
	}

	printDangerous(out)

	_, _ = fmt.Fprintf(out, "To stop ghostpsy changing anything: create /etc/ghostpsy/%s\n",
		action.SwitchFileName)
	_, _ = fmt.Fprintf(out, "To protect one service: add its name to %s\n", action.ProtectedFileName)
}

// printDangerous lists what ghostpsy will explain but never do.
//
// It belongs in the same output as the rest. A person deciding whether to trust
// this agent is as interested in where it stops as in what it does — and somebody
// who wants one of these changes gets the commands here, without asking us.
func printDangerous(out io.Writer) {
	dangerous := confedit.Dangerous()
	if len(dangerous) == 0 {
		return
	}

	_, _ = fmt.Fprintf(out, "It will never make these changes itself. "+
		"Only you can judge whether your server survives them, so here is how to do "+
		"them by hand:\n\n")
	for _, d := range dangerous {
		_, _ = fmt.Fprintf(out, "%s %s\n", d.Setting, d.Value)
		_, _ = fmt.Fprintf(out, "  The risk      %s\n", d.Risk)
		_, _ = fmt.Fprintf(out, "  Check first   %s\n", d.CheckFirst)
		_, _ = fmt.Fprintf(out, "  Commands\n")
		for _, line := range d.Commands {
			_, _ = fmt.Fprintf(out, "    %s\n", line)
		}
		_, _ = fmt.Fprintln(out)
	}
}

func undoWords(r action.Reversibility) string {
	switch r {
	case action.ReverseFull:
		return "yes, fully"
	case action.ReversePartial:
		return "partly"
	case action.ReverseNone:
		return "no"
	}
	return string(r)
}
