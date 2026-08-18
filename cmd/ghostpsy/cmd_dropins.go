//go:build linux

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

const dropInsLongHelp = `Prints the configuration files ghostpsy would install, and their exact content.

The sudo rule names each of these files by path and copies it without reading it,
so this is how you check what that copy would put on your server. Nothing here is
computed at the time of the fix: the content is fixed when the agent is installed,
owned by root and read-only, which is what stops the agent choosing it later.

Printing changes nothing. --write installs the files and needs root; setup does
it for you.
`

func newDropInsCommand() *cobra.Command {
	var write bool

	cmd := &cobra.Command{
		Use:   "dropins",
		Short: "Print the configuration files ghostpsy can install",
		Long:  dropInsLongHelp,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if write {
				return writeDropIns(cmd.OutOrStdout(), "")
			}
			return printDropIns(cmd.OutOrStdout(), "")
		},
	}
	cmd.Flags().BoolVar(&write, "write", false, "install the files (needs root)")
	return cmd
}

// printDropIns shows every file, where it goes, and what is in it.
//
// root is "" in production and a temporary directory in tests, the same seam
// confedit.Applicable uses — so a test can describe a server that has an SSH
// drop-in directory and no apt one.
func printDropIns(out io.Writer, root string) error {
	// What this server can use, not what this agent version knows. A machine with
	// no apt.conf.d should not be offered an apt fix.
	changes := confedit.Applicable(root)
	_, err := fmt.Fprintf(out,
		"These %d files are the only configuration ghostpsy can install on this server,\n"+
			"and this is their exact content. Nothing else can be written.\n\n", len(changes))
	if err != nil {
		return err
	}

	for _, c := range changes {
		drop := c.DropIn()
		if _, err := fmt.Fprintf(out, "%s = %s\n", c.Setting.Key, c.Value); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  from  %s\n", drop.Source); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  to    %s  (mode %s)\n", drop.Dest, drop.Mode); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "%s\n", indent(drop.Content)); err != nil {
			return err
		}
	}
	return nil
}

// writeDropIns installs the files. root is "" in production.
func writeDropIns(out io.Writer, root string) error {
	written, err := confedit.WriteDropIns(root)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Wrote %d files to %s, owned by root and read-only.\n",
		len(written), confedit.DropInSourceDir())
	return err
}

// indent offsets a file's content so it cannot be mistaken for our own output.
func indent(content string) string {
	var b []byte
	b = append(b, "      |"...)
	for i := 0; i < len(content); i++ {
		b = append(b, content[i])
		if content[i] == '\n' && i != len(content)-1 {
			b = append(b, "      |"...)
		}
	}
	return string(b)
}
