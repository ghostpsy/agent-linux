//go:build linux

package main

import (
	"fmt"

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
