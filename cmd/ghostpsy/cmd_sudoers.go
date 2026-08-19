//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// agentUser is the locked system account the agent runs as. It cannot log in.
const agentUser = "ghostpsy"

// installedGrantPath is where the grant lives once a host has one.
const installedGrantPath = "/etc/sudoers.d/ghostpsy"

// errNoGrantInstalled means there is no grant file at all. That is a different
// situation from a stale one, and it needs different advice.
var errNoGrantInstalled = errors.New("no sudo rule is installed")

func newSudoersCommand() *cobra.Command {
	var check, diff bool
	var path string

	cmd := &cobra.Command{
		Use:   "sudoers",
		Short: "Print the sudo rule the agent needs, and install nothing",
		Long: "Prints the exact list of commands ghostpsy may run as root on this server.\n" +
			"It changes nothing. Read it, then decide whether to install it.\n\n" +
			"The list is generated from this agent version and from what is actually\n" +
			"installed here, so it grants nothing for software you do not have.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case check:
				return runSudoersCheck(cmd, path)
			case diff:
				return runSudoersDiff(cmd, path)
			default:
				// A truncated grant file is worse than none: report a broken
				// pipe rather than let the caller install half a rule.
				_, err := fmt.Fprint(cmd.OutOrStdout(), sudoersFile())
				return err
			}
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "compare the installed rule with what this version needs")
	cmd.Flags().BoolVar(&diff, "diff", false, "show what would change in the installed rule")
	cmd.Flags().StringVar(&path, "path", installedGrantPath, "the installed rule to compare against")

	return cmd
}

func runSudoersCheck(cmd *cobra.Command, path string) error {
	drifted, err := sudoersHasDrifted(path)
	if errors.Is(err, errNoGrantInstalled) {
		return fmt.Errorf("no sudo rule is installed at %s.\n"+
			"Install one with: ghostpsy sudoers | sudo tee %s", path, path)
	}
	if err != nil {
		return err
	}
	if drifted {
		return fmt.Errorf("the sudo rule at %s no longer matches what this agent needs.\n"+
			"See what changed with: ghostpsy sudoers --diff\n"+
			"Update it with:        ghostpsy sudoers | sudo tee %s", path, path)
	}

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "The sudo rule at %s is up to date.\n", path)
	return err
}

func runSudoersDiff(cmd *cobra.Command, path string) error {
	return runSudoersDiffWith(cmd.OutOrStdout(), path, readInstalledGrant)
}

// runSudoersDiffWith takes the reader, for the same reason the drift check does: the
// agent user cannot open a 0440 root:root file, so the read has to go through the
// privileged path.
//
// This used to call os.ReadFile. The drift check prints "See what changed with:
// ghostpsy sudoers --diff", and that command then answered "permission denied" for the
// only user that ever runs the check.
func runSudoersDiffWith(out io.Writer, path string, read func(string) ([]byte, error)) error {
	installed, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		installed = nil
	} else if err != nil {
		return err
	}

	for _, line := range grantDiff(string(installed), sudoersFile()) {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

// grantDiff reports the lines that would leave the installed rule and the ones
// that would join it. Order does not matter in a sudoers file, so comparing
// sets keeps the output to what actually changes.
func grantDiff(installed, wanted string) []string {
	present := map[string]bool{}
	for _, line := range strings.Split(installed, "\n") {
		present[line] = true
	}
	keep := map[string]bool{}
	for _, line := range strings.Split(wanted, "\n") {
		keep[line] = true
	}

	var out []string
	for _, line := range strings.Split(installed, "\n") {
		if line != "" && !keep[line] {
			out = append(out, "- "+line)
		}
	}
	for _, line := range strings.Split(wanted, "\n") {
		if line != "" && !present[line] {
			out = append(out, "+ "+line)
		}
	}
	return out
}

// sudoersHasDrifted reports whether the installed grant still matches what this
// agent version needs. Drift is not cosmetic: a collector that lost its
// privilege goes quiet, and nobody connects that to an upgrade weeks earlier.
func sudoersHasDrifted(path string) (bool, error) {
	return sudoersHasDriftedWith(path, readInstalledGrant)
}

// readInstalledGrant returns the installed grant's text.
//
// Root reads the file. The agent user cannot, and no permission change fixes it:
// the grant is 0440 root:root, and on an SELinux host making it group-readable is
// still refused — measured on CentOS 6.10, where sudo accepted the file and the
// agent was still denied. So the unprivileged path asks the agent itself,
// through the same allowlist every other privileged read goes through.
//
// Until a host's grant includes that entry the read fails, and the drift stays
// unreported rather than guessed. Reinstalling the rule fixes it.
func readInstalledGrant(path string) ([]byte, error) {
	// Whether a grant exists at all is a different question from what is in it, and
	// it needs no privilege. Asking the privileged reader first turned "no grant is
	// installed" into "the agent binary is not on this host", which is a true
	// sentence about something nobody asked about.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if os.Geteuid() == 0 {
		return os.ReadFile(path)
	}
	res, err := privexec.Run(context.Background(), privexec.ReadGrant)
	if err != nil {
		return nil, err
	}
	return res.Stdout, nil
}

// sudoersHasDriftedWith takes the reader, so the comparison can be tested
// without a privileged host.
func sudoersHasDriftedWith(path string, read func(string) ([]byte, error)) (bool, error) {
	installed, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, errNoGrantInstalled
	}
	if err != nil {
		return false, err
	}
	// Compare the grants, not the bytes. A byte comparison also covers the
	// header comment, so editing that text in a future release would report
	// every host as drifted while nothing about its privileges changed.
	return len(grantDiff(string(installed), sudoersFile())) > 0, nil
}

func sudoersFile() string {
	header := "# /etc/sudoers.d/ghostpsy — generated by `ghostpsy sudoers`\n" +
		"#\n" +
		"# Every command ghostpsy may run as root on this server is listed below,\n" +
		"# and it may run nothing else. The agent refuses any command that is not\n" +
		"# here, before sudo is ever asked.\n" +
		"#\n" +
		"# Install with:  ghostpsy sudoers | sudo tee /etc/sudoers.d/ghostpsy\n" +
		"# Check it with: sudo visudo -c -f /etc/sudoers.d/ghostpsy\n" +
		"#\n" +
		"# After upgrading the agent, `ghostpsy sudoers --check` says whether this\n" +
		"# file still matches what it needs.\n\n"

	grant := privexec.Sudoers(agentUser)
	if grant == "" {
		return header + "# None of the software ghostpsy inspects with elevated rights is\n" +
			"# installed here, so nothing on this server needs a sudo rule.\n" +
			"# Install this file anyway if you like; it grants nothing.\n"
	}

	return header + grant
}
