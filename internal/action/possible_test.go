//go:build linux

package action

import (
	"slices"
	"testing"
)

// The agent says which fixes this machine can actually take.
//
// The bug this was written for. The plan is built in the cloud from the scan
// report, which says what is wrong but not what this server can do about it. So
// harden_ssh_config was offered on an Ubuntu 14.04 host that has neither systemd
// to reload sshd nor an sshd_config.d to drop a file into. The person ticked it,
// approved it, and only then was told it was never going to work.
//
// The agent already knows — it is what pickVariant decides — so it says so once,
// with the scan, instead of the cloud guessing in Go's place.
func TestPossibleOnListsOnlyWhatThisMachineCanTake(t *testing.T) {
	deps := testDeps(&fakeExec{})
	// A machine with nothing installed can take nothing that needs a tool.
	deps.Installed = func(string) bool { return false }

	possible := PossibleOn(deps)

	for _, action := range All() {
		needsTool := false
		for _, variant := range action.Variants {
			if variant.Needs == "" {
				needsTool = false
				break
			}
			needsTool = true
		}
		if needsTool && slices.Contains(possible, action.Type) {
			t.Errorf("%s needs a tool this machine does not have, so it must not be offered", action.Type)
		}
	}
}

func TestPossibleOnListsAnActionWhoseToolIsThere(t *testing.T) {
	deps := testDeps(&fakeExec{})
	deps.Installed = func(string) bool { return true }

	possible := PossibleOn(deps)

	if len(possible) != len(All()) {
		t.Errorf("with every tool present, every action is possible: got %d of %d",
			len(possible), len(All()))
	}
}

// The list is what the cloud filters on, so a name that does not match an action
// filters everything out and the plan silently empties.
func TestPossibleOnUsesTheActionTypeTheCloudKnows(t *testing.T) {
	deps := testDeps(&fakeExec{})
	deps.Installed = func(string) bool { return true }

	known := make([]string, 0, len(All()))
	for _, action := range All() {
		known = append(known, action.Type)
	}

	for _, name := range PossibleOn(deps) {
		if !slices.Contains(known, name) {
			t.Errorf("%q is not an action type", name)
		}
	}
}
