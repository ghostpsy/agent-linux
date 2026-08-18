//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// `ghostpsy actions` is the answer to "prove it only does what you say".
//
// It had no test, and it crashed the first time a setting had no safe value at
// all: it printed the allowed-values pattern for every setting, and an advice-only
// one has none. A nil regexp, a segfault, and the one command whose whole job is
// building trust dying in front of the person deciding whether to trust us.
func TestActionsPrintsWithoutCrashingOnASettingThatHasNoSafeValue(t *testing.T) {
	advisory := 0
	for _, s := range confedit.All() {
		if s.Allow == nil {
			advisory++
		}
	}
	if advisory == 0 {
		t.Skip("no advice-only setting to exercise")
	}

	var out bytes.Buffer
	printActions(&out)

	if out.Len() == 0 {
		t.Fatal("printed nothing")
	}
}

// An advice-only setting must not claim to have allowed values. "Allowed values
// <nil>" is worse than saying nothing, and saying nothing is worse than the truth.
func TestActionsSaysPlainlyWhichSettingsItNeverChangesItself(t *testing.T) {
	var out bytes.Buffer
	printActions(&out)
	printed := out.String()

	if strings.Contains(printed, "<nil>") || strings.Contains(printed, "Allowed values \n") {
		t.Errorf("an advice-only setting printed an empty pattern:\n%s", printed)
	}
	if !strings.Contains(printed, "ghostpsy never sets this itself") {
		t.Error("an advice-only setting has to say so, or the list reads as if we would set it")
	}
}

// Every dangerous change reaches the printed list. A person who wants one of them
// gets the commands here, without asking us at all.
func TestActionsPrintsEveryDangerousChangeWithItsCommands(t *testing.T) {
	var out bytes.Buffer
	printActions(&out)
	printed := out.String()

	for _, d := range confedit.Dangerous() {
		if !strings.Contains(printed, d.Setting+" "+d.Value) {
			t.Errorf("%s %s is missing from the printed list", d.Setting, d.Value)
		}
		if !strings.Contains(printed, d.CheckFirst) {
			t.Errorf("%s %s printed without the thing to check first", d.Setting, d.Value)
		}
	}
}
