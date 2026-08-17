//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/collect/identity"
)

// newReadShadowCommand is the one place the agent delegates a privileged file
// read to itself.
//
// /etc/shadow cannot be named as an exact sudo command, so the alternative
// would be granting `cat /etc/shadow` — which would pull real password hashes
// through the agent. This prints only the counts, and the sudoers file says so
// on the line above the grant.
//
// It is meant to be run through sudo by the agent, not typed by a person.
func newReadShadowCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "read-shadow",
		Short:  "Print the account summary from /etc/shadow, without any password material",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := identity.ShadowSummaryJSON()
			if err != nil {
				return fmt.Errorf("could not summarise the shadow file: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
			return err
		},
	}
}

// newReadSudoersCommand is the second and, so far, last delegated read. A
// sudoers file says who can become root here; the agent needs the counts, not
// the text, so only the counts are printed.
func newReadSudoersCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "read-sudoers",
		Short:  "Print the sudoers audit counts, without any rule text",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := identity.SudoersAuditJSON()
			if err != nil {
				return fmt.Errorf("could not summarise the sudoers files: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
			return err
		},
	}
}

// newReadGrantCommand is the third delegated read, and the only one whose
// subject is a file ghostpsy itself installed.
//
// The agent needs its own grant to say whether the grant is out of date. It
// cannot read it: /etc/sudoers.d/ghostpsy is 0440 root:root, and on an SELinux
// host even making it group-readable is refused — measured on CentOS 6.10, where
// sudo accepted the file and the agent still could not open it. There is no
// secret here: this prints back the very text that lists what the agent may do.
func newReadGrantCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "read-grant",
		Short:  "Print the installed sudo rule, so the agent can check it is current",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			installed, err := os.ReadFile(installedGrantPath)
			if err != nil {
				return fmt.Errorf("could not read %s: %w", installedGrantPath, err)
			}
			_, err = cmd.OutOrStdout().Write(installed)
			return err
		},
	}
}
