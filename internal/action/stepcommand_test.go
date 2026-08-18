//go:build linux

package action

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// A step's command can name its parameters, the same way its arguments already do.
//
// It exists because a parameter filled in at run time becomes a wildcard in the sudo
// grant, and a wildcard in a sudoers argument matches `/` as well — measured on
// debian-13, `cat /tmp/gpd/*.conf` read a 0600 file two directories up. So instead of
// one command taking any value, there is one declared command per value, and the
// choice of which to run moves here, where it can be refused with a reason.
//
// The templates below use the real declarations rather than invented ones, so this
// tests the mechanism against the catalogue a customer's server would have.

const maxAuthTriesTemplate = privexec.ID("config.install.ssh.max_auth_tries={value}")

func TestAStepsCommandCanNameItsParameters(t *testing.T) {
	got, err := stepCommand(
		Step{Command: maxAuthTriesTemplate},
		map[string]string{"value": "5"},
	)
	if err != nil {
		t.Fatalf("resolving the command failed: %v", err)
	}
	want := privexec.ID("config.install.ssh.max_auth_tries=5")
	if got != want {
		t.Fatalf("resolved to %q, want %q", got, want)
	}
}

func TestAStepsCommandIsUsedAsItIsWhenItNamesNothing(t *testing.T) {
	got, err := stepCommand(Step{Command: privexec.SSHTestConfig}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != privexec.SSHTestConfig {
		t.Fatalf("resolved to %q", got)
	}
}

// The refusal somebody will actually meet: a value or a service this server's grant
// does not cover. The message has to say that, not "command not declared", because
// the person reading it is deciding what to do next.
func TestACombinationWithNoGrantIsRefusedWithAReason(t *testing.T) {
	_, err := stepCommand(
		Step{Command: maxAuthTriesTemplate},
		map[string]string{"value": "7"},
	)
	if err == nil {
		t.Fatal("a value with no declared command was accepted")
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("the message does not say what was asked for: %v", err)
	}
	if !strings.Contains(err.Error(), "this server") {
		t.Errorf("the message does not say where the limit is: %v", err)
	}
}

func TestAMissingParameterIsReportedRatherThanLeftInThePlaceholder(t *testing.T) {
	_, err := stepCommand(Step{Command: maxAuthTriesTemplate}, nil)
	if err == nil {
		t.Fatal("a step with no value for its parameter resolved anyway")
	}
	if !strings.Contains(err.Error(), "value") {
		t.Errorf("the message does not name the missing parameter: %v", err)
	}
}

// A templated command must survive the same check as a literal one, or a typo in a
// placeholder reaches a customer's server and fails there.
func TestATemplatedCommandIsCheckedAtStartup(t *testing.T) {
	a := Action{
		Type:   "test_thing",
		Params: []Param{{Name: "value", Why: "a value", Allow: regexp.MustCompile(`^[0-9]$`)}},
	}

	// A placeholder the action does not declare.
	err := checkStep(a, Step{Why: "do it", Command: privexec.ID("config.install.ssh.max_auth_tries={nope}")})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("an undeclared placeholder was accepted: %v", err)
	}

	// A template no declared command could ever match.
	err = checkStep(a, Step{Why: "do it", Command: privexec.ID("config.install.not.a.setting={value}")})
	if err == nil {
		t.Error("a template that matches no declared command was accepted")
	}

	// And the real one passes.
	if err := checkStep(a, Step{Why: "do it", Command: maxAuthTriesTemplate}); err != nil {
		t.Errorf("the real template was rejected: %v", err)
	}
}
