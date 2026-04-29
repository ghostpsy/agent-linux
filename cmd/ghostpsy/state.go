//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/state"
)

// ensureState loads /var/lib/ghostpsy/state.json or seeds it on first run.
//
// MachineUUID prefers /etc/machine-id (stable per OS install). When that
// file is missing (e.g. some minimal containers), a random UUID is
// generated and persisted so the same identity is used on subsequent
// scans.
func ensureState(logger *actionlog.Logger) *state.AgentState {
	st, err := state.Load()
	if err == nil {
		return st
	}
	mid := uuid.NewString()
	midSource := "random"
	if osMid, ok := state.MachineUUIDFromOS(); ok {
		mid = osMid
		midSource = "OS machine-id (/etc/machine-id or /var/lib/dbus/machine-id)"
	}
	s := &state.AgentState{MachineUUID: mid, ScanSeq: 0}
	logger.Step("local-modifying", state.Path(),
		"Initializing local agent identity at "+state.Path(), nil)
	if err := state.Save(s); err != nil {
		printErrorLine(fmt.Sprintf("save state: %v", err))
		os.Exit(1)
	}
	printSuccessLine("First run: registered local identity for this host.")
	fmt.Println("Machine UUID:", mid, "("+midSource+")")
	printMutedLine("State file: " + state.Path())
	return s
}
