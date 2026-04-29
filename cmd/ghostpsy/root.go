//go:build linux

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/version"
)

const rootLongHelp = `ghostpsy collects allowlisted server metadata and sends it after operator preview.

Commands:
  register   First-time setup: consume a 24h bootstrap token, run the first scan, store the persistent agent token at /etc/ghostpsy/agent.conf.
  scan       Build payload, print JSON for review, optionally POST to API.
  cron       Install, remove, or inspect the scheduled-scan timer.
  update     Check for and install a new agent release (Ed25519-signed).
  version    Print version, release date (build), and architecture.

Environment:
  GHOSTPSY_API_URL          Base URL for Ghostpsy Cloud API (default https://api.ghostpsy.com; override for local dev).
  GHOSTPSY_BOOTSTRAP_TOKEN  Bootstrap token for ` + "`ghostpsy register`" + ` (alternative to --bootstrap=<token>).
`

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ghostpsy",
		Short: "Legacy server telemetry (allowlisted)",
		Long:  rootLongHelp,
		Run:   runRootOrShowUsage,
	}
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.Flags().BoolP("version", "v", false, "print version and exit")
	root.AddCommand(newScanCommand())
	root.AddCommand(newRegisterCommand())
	root.AddCommand(newCronCommand())
	root.AddCommand(newUpdateCommand())
	root.AddCommand(newVersionCommand())
	return root
}

func runRootOrShowUsage(cmd *cobra.Command, _ []string) {
	showVer, err := cmd.Flags().GetBool("version")
	if err != nil {
		printErrorLine("invalid flags")
		os.Exit(1)
	}
	if showVer {
		cmd.Println(version.Summary())
		return
	}
	cmd.SetOut(cmd.ErrOrStderr())
	_ = cmd.Usage()
	os.Exit(1)
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, release date (build), and architecture",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(version.Summary())
		},
	}
}
