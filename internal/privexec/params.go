//go:build linux

package privexec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A fix has to name what it acts on: which service to restart, which config file
// to correct, how far back to trim the journal. Reads never needed that — every
// command in the original catalogue was fixed text — but an action does, and that
// value is the only part of a privileged command the cloud gets to influence.
//
// So it is the part that is checked hardest. A declared parameter carries the
// exact shape it accepts, the substituted value stays one argument, and no shell
// is involved anywhere. "The cloud cannot make the agent run something else" is
// therefore true by construction, in the same way ErrNotDeclared already makes
// "the agent cannot invent a root command" true.

// ErrBadParam means a value did not match what the command declared, or a
// declared value was missing, or one arrived that nothing declared.
var ErrBadParam = errors.New("privexec: parameter is not allowed")

// Param is one value a caller fills in when running a declared command.
type Param struct {
	// Name is what the placeholder in Args is written as: {name}.
	Name string

	// Why says, in plain words, what may go here. The grant file can only show
	// sudo a wildcard, so this sentence is the only place a sysadmin reading it
	// can learn what the agent will actually put there.
	Why string

	// Allow is the only shape accepted. It is required, and it must be anchored
	// — an unanchored pattern matches a substring, which would let anything
	// through as long as it contained something allowed.
	Allow *regexp.Regexp
}

// Values are the parameter values for one invocation, by parameter name.
type Values map[string]string

// placeholder finds {name} in a declared argument.
var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// fill checks the supplied values against what the command declared and returns
// the real argument list.
//
// Every declared parameter must be present and match its rule, and nothing may
// arrive that was not declared. An extra value is refused rather than dropped:
// silently ignoring it would let a caller believe it had an effect, and the
// first time that belief is wrong it is wrong on a customer's server.
func fill(declared Command, values Values) ([]string, error) {
	if err := checkValues(declared, values); err != nil {
		return nil, err
	}

	args := make([]string, 0, len(declared.Args))
	for _, arg := range declared.Args {
		// Each argument is substituted whole and appended as one element, so a
		// value containing a space cannot become a second argument.
		args = append(args, placeholder.ReplaceAllStringFunc(arg, func(match string) string {
			return values[placeholder.FindStringSubmatch(match)[1]]
		}))
	}
	return args, nil
}

func checkValues(declared Command, values Values) error {
	for _, param := range declared.Params {
		value, given := values[param.Name]
		if !given {
			return fmt.Errorf("%w: %q was not given", ErrBadParam, param.Name)
		}
		if !param.Allow.MatchString(value) {
			// The value is deliberately not repeated. It came from outside, and
			// a log line is read by a person and sometimes by a terminal.
			return fmt.Errorf("%w: %q is not one of the shapes %s accepts",
				ErrBadParam, param.Name, param.Name)
		}
	}
	for name := range values {
		if !declaresParam(declared, name) {
			return fmt.Errorf("%w: nothing declares %q", ErrBadParam, name)
		}
	}
	return nil
}

func declaresParam(declared Command, name string) bool {
	for _, param := range declared.Params {
		if param.Name == name {
			return true
		}
	}
	return false
}

// checkPlaceholders reports a command whose Args and Params disagree.
//
// Either mistake is silent in production: an unfilled placeholder would be
// passed through literally as {unit}, and a parameter no argument uses would be
// validated and then thrown away. Both surface here, at startup.
func checkPlaceholders(id ID, c Command) error {
	used := map[string]bool{}
	for _, arg := range c.Args {
		for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
			used[match[1]] = true
		}
	}

	for name := range used {
		if !declaresParam(c, name) {
			return fmt.Errorf("command %q uses {%s} but declares no such parameter", id, name)
		}
	}
	for _, param := range c.Params {
		if param.Allow == nil {
			return fmt.Errorf("command %q parameter %q declares no allowed shape", id, param.Name)
		}
		if !isAnchored(param.Allow.String()) {
			return fmt.Errorf("command %q parameter %q is not anchored with ^ and $", id, param.Name)
		}
		if !used[param.Name] {
			return fmt.Errorf("command %q declares parameter %q but no argument uses it", id, param.Name)
		}
	}
	return nil
}

// isAnchored reports whether a pattern matches whole values only. An unanchored
// pattern matches a substring, so `[a-z]+` would happily accept `nginx; reboot`.
func isAnchored(pattern string) bool {
	return strings.HasPrefix(pattern, "^") && strings.HasSuffix(pattern, "$")
}

// grantArgs renders a command's arguments as the grant file must show them.
//
// sudo knows nothing about our rules, so a filled-in value can only appear as a
// wildcard. It still bounds the shape: sudo matches argument by argument, so
// `systemctl restart *` allows exactly one more argument after restart.
func grantArgs(c Command) []string {
	args := make([]string, 0, len(c.Args))
	for _, arg := range c.Args {
		args = append(args, placeholder.ReplaceAllString(arg, "*"))
	}
	return args
}
