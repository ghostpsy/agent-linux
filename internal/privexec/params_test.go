//go:build linux

package privexec

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// A fix has to name what it acts on — which service to restart, how far back to
// trim the journal. That value comes from the cloud, so it is the one part of a
// privileged command an attacker could try to steer.
func TestRunWithFillsADeclaredParameter(t *testing.T) {
	declareForTest(t, ID("test:param"), Command{
		Binary: "/bin/echo",
		Args:   []string{"unit={unit}"},
		Params: []Param{{Name: "unit", Allow: regexp.MustCompile(`^[a-z]+$`)}},
	})

	res, err := RunWith(context.Background(), ID("test:param"), Values{"unit": "nginx"})

	if err != nil {
		t.Fatalf("expected the declared command to run, got error: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "unit=nginx" {
		t.Fatalf("expected stdout %q, got %q", "unit=nginx", got)
	}
}

func TestRunWithRefusesAValueThatFailsItsRule(t *testing.T) {
	declareForTest(t, ID("test:bad-value"), Command{
		Binary: "/bin/echo",
		Args:   []string{"{unit}"},
		Params: []Param{{Name: "unit", Allow: regexp.MustCompile(`^[a-z]+$`)}},
	})

	hostile := []string{
		"nginx; rm -rf /",
		"nginx && reboot",
		"../../etc/shadow",
		"$(id)",
		"nginx\nreboot",
		"--force",
		"",
	}
	for _, value := range hostile {
		_, err := RunWith(context.Background(), ID("test:bad-value"), Values{"unit": value})
		if !errors.Is(err, ErrBadParam) {
			t.Fatalf("expected %q to be refused with ErrBadParam, got: %v", value, err)
		}
	}
}

func TestRunWithRefusesAMissingParameter(t *testing.T) {
	declareForTest(t, ID("test:missing"), Command{
		Binary: "/bin/echo",
		Args:   []string{"{unit}"},
		Params: []Param{{Name: "unit", Allow: regexp.MustCompile(`^[a-z]+$`)}},
	})

	_, err := RunWith(context.Background(), ID("test:missing"), nil)

	if !errors.Is(err, ErrBadParam) {
		t.Fatalf("expected a missing parameter to be refused, got: %v", err)
	}
}

// An extra value is refused rather than ignored. Ignoring it would let a caller
// believe it had an effect, and the first time that belief is wrong it is wrong
// on a customer's server.
func TestRunWithRefusesAnUndeclaredParameter(t *testing.T) {
	declareForTest(t, ID("test:extra"), Command{Binary: "/bin/echo", Args: []string{"hello"}})

	_, err := RunWith(context.Background(), ID("test:extra"), Values{"unit": "nginx"})

	if !errors.Is(err, ErrBadParam) {
		t.Fatalf("expected an undeclared parameter to be refused, got: %v", err)
	}
}

// A filled value stays one argument. No shell is involved, so spaces inside a
// value cannot split it into a second command — but the rule that keeps it one
// argument has to be tested, not assumed.
func TestRunWithKeepsAFilledValueAsOneArgument(t *testing.T) {
	declareForTest(t, ID("test:one-arg"), Command{
		Binary: "/bin/echo",
		Args:   []string{"-n", "{text}"},
		Params: []Param{{Name: "text", Allow: regexp.MustCompile(`^[a-z ]+$`)}},
	})

	res, err := RunWith(context.Background(), ID("test:one-arg"), Values{"text": "two words"})

	if err != nil {
		t.Fatalf("expected the command to run, got error: %v", err)
	}
	if got := string(res.Stdout); got != "two words" {
		t.Fatalf("expected the value to arrive as one argument, got %q", got)
	}
}

// The grant on the host has to allow the whole shape of the command, and sudo
// has no idea what our rule says. A wildcard is the only thing it understands,
// and it still bounds how many arguments may follow.
func TestSudoersUsesAWildcardForADeclaredParameter(t *testing.T) {
	declareForTest(t, ID("test:grant-param"), Command{
		Binary: "/bin/echo",
		Args:   []string{"restart", "{unit}"},
		Params: []Param{{Name: "unit", Allow: regexp.MustCompile(`^[a-z]+$`)}},
	})

	got := Sudoers("ghostpsy")

	want := "ghostpsy ALL=(root) NOPASSWD: /bin/echo restart *"
	if !strings.Contains(got, want) {
		t.Fatalf("expected the grant to contain %q, got:\n%s", want, got)
	}
}

// The person reading /etc/sudoers.d/ghostpsy sees a wildcard. They are entitled
// to know what the agent will actually put there.
func TestSudoersExplainsWhatMayFillAWildcard(t *testing.T) {
	declareForTest(t, ID("test:grant-why"), Command{
		Binary: "/bin/echo",
		Args:   []string{"{unit}"},
		Why:    "restart a service that has failed",
		Params: []Param{{
			Name:  "unit",
			Why:   "the name of one systemd service, letters and dashes only",
			Allow: regexp.MustCompile(`^[a-z-]+$`),
		}},
	})

	got := Sudoers("ghostpsy")

	if !strings.Contains(got, "the name of one systemd service, letters and dashes only") {
		t.Fatalf("expected the grant to explain what may fill the wildcard, got:\n%s", got)
	}
}

// A command whose Args use a placeholder no Param declares can never be filled.
// That is a programming error, and it must fail at startup rather than as a
// broken fix on a customer's server.
func TestDeclarePanicsOnAPlaceholderWithNoParameter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected declare to panic on a placeholder with no matching parameter")
		}
	}()
	declare(ID("test:orphan-placeholder"), Command{Binary: "/bin/echo", Args: []string{"{nope}"}})
}

func TestDeclarePanicsOnAParameterThatAppearsNowhere(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected declare to panic on a parameter no argument uses")
		}
	}()
	declare(ID("test:unused-param"), Command{
		Binary: "/bin/echo",
		Args:   []string{"hello"},
		Params: []Param{{Name: "unit", Allow: regexp.MustCompile(`^.+$`)}},
	})
}
