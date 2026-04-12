//go:build linux

// ghostpsy collects allowlisted server metadata and sends it after operator preview.
package main

import "os"

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		printErrorLine(err.Error())
		os.Exit(1)
	}
}
