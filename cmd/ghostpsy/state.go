//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/state"
)

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
	claim := strings.ToUpper(uuid.NewString()[:8])
	s := &state.AgentState{
		MachineUUID: mid,
		ClaimCode:   claim,
		ScanSeq:     0,
	}
	logger.Step("local-modifying", "~/.config/ghostpsy/agent.json", "Initializing local agent identity file in ~/.config/ghostpsy/agent.json", nil)
	if err := state.Save(s); err != nil {
		printErrorLine(fmt.Sprintf("save state: %v", err))
		os.Exit(1)
	}
	printSuccessLine("First run: registered this host.")
	fmt.Println("Machine UUID:", mid, "("+midSource+")")
	fmt.Println("Claim code (paste in dashboard while logged in):", claim)
	printMutedLine("State file: ~/.config/ghostpsy/agent.json")
	return s
}
