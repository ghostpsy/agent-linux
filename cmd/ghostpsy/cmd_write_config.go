//go:build linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// newWriteConfigCommand is the one place the agent changes a config file.
//
// A sudo rule cannot say "may set this one line of this one file", so the grant
// names this command and the list of what may be touched lives in
// internal/confedit, where it can be read and tested. It is the same shape as the
// delegated reads next door: the file the sysadmin can read says what we do, and
// the code is what enforces it.
//
// The key names a declared setting. It never names a path, so no path can arrive
// from the cloud. A value outside the declared shape is refused before anything is
// opened.
//
// It is meant to be run through sudo by the agent, not typed by a person.
func newWriteConfigCommand() *cobra.Command {
	var (
		mode  string
		key   string
		value string
	)

	cmd := &cobra.Command{
		Use:    "write-config",
		Short:  "Preview, apply, undo or check one declared configuration setting",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runWriteConfig(mode, key, value)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), out)
			return err
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "", "preview, apply, restore or verify")
	cmd.Flags().StringVar(&key, "key", "", "which declared setting")
	cmd.Flags().StringVar(&value, "value", "", "the value to set (not used by restore)")
	return cmd
}

// The four things this command can do. Restore needs no value: it puts back the
// copy that apply took, whatever was in it.
const (
	writeConfigPreview = "preview"
	writeConfigApply   = "apply"
	writeConfigRestore = "restore"
	writeConfigVerify  = "verify"
)

func runWriteConfig(mode, key, value string) (string, error) {
	if mode == writeConfigRestore {
		setting, known := confedit.Lookup(key)
		if !known {
			return "", fmt.Errorf("%q is not a setting ghostpsy is allowed to change", key)
		}
		return confedit.Restore(setting)
	}

	// Everything else needs a value, and the value is checked against the
	// setting's declared shape before a single file is opened.
	setting, err := confedit.Check(key, value)
	if err != nil {
		return "", err
	}

	switch mode {
	case writeConfigPreview:
		return confedit.Preview(setting, value)
	case writeConfigApply:
		return confedit.Apply(setting, value)
	case writeConfigVerify:
		return confedit.Verify(setting, value)
	}
	return "", fmt.Errorf("%q is not something write-config can do", mode)
}
