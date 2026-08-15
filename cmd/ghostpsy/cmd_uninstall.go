//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/service"
)

// uninstallPaths is every path the installer creates. Keeping them in one
// struct is what lets --purge promise that nothing is left behind: a path that
// is not listed here cannot be removed, so adding one to the installer without
// adding it here shows up as a leftover.
type uninstallPaths struct {
	Binary  string
	Sudoers string
	Config  string
	State   string
}

func defaultUninstallPaths() uninstallPaths {
	return uninstallPaths{
		Binary:  "/usr/local/bin/ghostpsy",
		Sudoers: "/etc/sudoers.d/ghostpsy",
		Config:  "/etc/ghostpsy",
		State:   "/var/lib/ghostpsy",
	}
}

func newUninstallCommand() *cobra.Command {
	var purge bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove ghostpsy from this server",
		Long: "Removes the service, the sudo rule and the agent.\n\n" +
			"Configuration and state are kept, so reinstalling later keeps this\n" +
			"machine's identity and its history in the dashboard.\n\n" +
			"Use --purge to remove those too. Your scan history stays in the\n" +
			"dashboard either way.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUninstall(cmd, purge)
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also remove the configuration, the state and the machine's identity")
	return cmd
}

func runUninstall(cmd *cobra.Command, purge bool) error {
	out := cmd.OutOrStdout()
	say := func(format string, a ...any) {
		// A broken pipe here does not change what was removed, and failing the
		// uninstall over it would leave the host half-cleaned.
		_, _ = fmt.Fprintf(out, format+"\n", a...)
	}

	if m, err := service.For(service.Detect()); err == nil {
		if err := m.Remove(); err != nil {
			return err
		}
		say("Stopped and removed the ghostpsy service")
	}

	removed, err := removeInstalledFiles(defaultUninstallPaths(), purge)
	if err != nil {
		return err
	}
	for _, p := range removed {
		say("Removed %s", p)
	}

	if purge {
		say("\nDone. Nothing of ghostpsy is left on this server.")
		say("Revoke this machine's token in the dashboard if you do not plan to reinstall.")
		return nil
	}
	say("\nDone. Configuration and state were kept, so a reinstall keeps this machine's history.")
	return nil
}

// removeInstalledFiles deletes what the installer created and reports what it
// actually removed. Removing something already gone is not a failure: uninstall
// has to finish whatever state it finds, or it leaves the host half-cleaned.
//
// The sudo rule goes first, deliberately. On a real host the binary could not
// be unlinked and the whole uninstall stopped there, leaving the privilege
// grant in place — a sudo rule for a tool you just removed is the worst
// possible leftover. For the same reason one failure does not stop the others;
// they are collected and reported at the end.
func removeInstalledFiles(paths uninstallPaths, purge bool) ([]string, error) {
	return removeInstalledFilesWith(paths, purge, os.RemoveAll)
}

// removeInstalledFilesWith takes the remover so the "one path is stuck"
// behaviour can be tested. Relying on file permissions does not work: the tests
// run as root, and root ignores them.
func removeInstalledFilesWith(paths uninstallPaths, purge bool, remove func(string) error) ([]string, error) {
	targets := []string{paths.Sudoers, paths.Binary}
	if purge {
		targets = append(targets, paths.Config, paths.State)
	}

	var removed []string
	var failures []string
	for _, p := range targets {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		if err := remove(p); err != nil {
			failures = append(failures, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		removed = append(removed, p)
	}

	if len(failures) > 0 {
		return removed, fmt.Errorf("could not remove: %s", strings.Join(failures, "; "))
	}
	return removed, nil
}
