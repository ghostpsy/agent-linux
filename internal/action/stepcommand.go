//go:build linux

package action

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// A command can be chosen by the values a person asked for.
//
// The sudo grant has to be literal: one line per thing that can happen, no wildcards.
// So `install` is declared once per setting-and-value pair, and a unit is declared
// once per service. Which leaves the question of which of those to run, and it is
// answered here rather than in the grant — where it would have to be a pattern.
//
// The refusal this produces is a feature, not an edge case. It is how a server says
// "the grant I have does not cover that", which is exactly what should happen when
// somebody asks us to restart a service we do not configure.

// commandPlaceholder matches {name} inside a command ID.
var commandPlaceholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// stepCommand resolves the command a step will run.
//
// An ID with no placeholder is returned unchanged, which is every step that acts on
// the machine as a whole rather than on one named thing.
func stepCommand(step Step, params map[string]string) (privexec.ID, error) {
	id := string(step.Command)
	if !commandPlaceholder.MatchString(id) {
		return step.Command, nil
	}

	var missing string
	filled := commandPlaceholder.ReplaceAllStringFunc(id, func(match string) string {
		name := commandPlaceholder.FindStringSubmatch(match)[1]
		value, given := params[name]
		if !given {
			missing = name
			return match
		}
		return value
	})
	if missing != "" {
		// Cannot happen for a declared action — checkAction rejects a step naming a
		// parameter the action does not have — so it is reported, not ignored.
		return "", fmt.Errorf("no value was given for %q", missing)
	}

	if !privexec.Declared(privexec.ID(filled)) {
		return "", fmt.Errorf(
			"this server does not allow that: %s. Its sudo rule lists every change "+
				"ghostpsy may make here, and this one is not on it. Run `ghostpsy sudoers` to read the list",
			describeAsked(id, filled))
	}
	return privexec.ID(filled), nil
}

// describeAsked says what was asked for, using the part of the ID that varied.
//
// The whole ID would be right and useless — `config.install.ssh.max_auth_tries=7`
// means nothing to somebody who has never read our source. The part that was filled
// in is the part they chose.
func describeAsked(template, filled string) string {
	prefix := commandPlaceholder.Split(template, -1)[0]
	return strings.TrimPrefix(filled, prefix)
}

// checkStepCommand rejects a step whose command could never resolve.
//
// A literal ID must be declared. A templated one must name parameters the action has,
// and must be able to match at least one declared command — a template with a typo in
// the middle resolves to nothing and would fail on a customer's server instead of at
// startup here.
func checkStepCommand(a Action, step Step) error {
	id := string(step.Command)
	if !commandPlaceholder.MatchString(id) {
		if !privexec.Declared(step.Command) {
			return fmt.Errorf("action %q step %q names command %q, which privexec does not declare",
				a.Type, step.Why, step.Command)
		}
		return nil
	}

	for _, match := range commandPlaceholder.FindAllStringSubmatch(id, -1) {
		if !declaresParam(a, match[1]) {
			return fmt.Errorf("action %q step %q names command %q, which refers to parameter %q "+
				"that the action does not declare", a.Type, step.Why, id, match[1])
		}
	}

	if !privexec.AnyDeclaredMatches(commandPattern(id)) {
		return fmt.Errorf("action %q step %q names command %q, and no declared command could "+
			"ever match it", a.Type, step.Why, id)
	}
	return nil
}

// commandPattern turns a templated ID into an expression matching the IDs it could
// resolve to.
//
// A placeholder matches anything, because the values are not all one word: a setting
// key is `ssh.max_auth_tries`, so config.install.{setting}={value} resolves to an ID
// with three dots in it. This is a startup sanity check that a template could ever
// match something — the real limit is privexec.Declared at the moment of running.
func commandPattern(id string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(id)
	// QuoteMeta escapes the braces, so match the escaped form too.
	quoted = strings.ReplaceAll(quoted, `\{`, `{`)
	quoted = strings.ReplaceAll(quoted, `\}`, `}`)
	quoted = commandPlaceholder.ReplaceAllString(quoted, `.+`)
	return regexp.MustCompile("^" + quoted + "$")
}
