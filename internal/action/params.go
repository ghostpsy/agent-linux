//go:build linux

package action

import (
	"fmt"
	"regexp"
	"strings"
)

// The values arrive from the cloud, so they are the only part of an action
// somebody outside this machine gets to influence. They are checked here before
// a single step is built, and checked again by privexec when the command line is
// assembled. Two checks, on purpose: privexec has other callers, and this
// package must not rely on somebody else's care.

// paramRef matches {name} in a step argument or in a summary.
var paramRef = regexp.MustCompile(`\{([a-z_]+)\}`)

func isParamRef(value string) bool {
	return paramRef.MatchString(value) && paramRef.FindString(value) == value
}

func refName(value string) string {
	return paramRef.FindStringSubmatch(value)[1]
}

// checkRequestParams enforces exactly what the action declared: every parameter
// present, every value the right shape, and nothing extra.
func checkRequestParams(a Action, params map[string]string) error {
	for _, p := range a.Params {
		value, given := params[p.Name]
		if !given {
			return fmt.Errorf("this fix needs to know %s, and no value was given", plainName(p))
		}
		if !p.Allow.MatchString(value) {
			// The value itself is deliberately not repeated. It came from
			// outside, and this sentence is shown to a person and written to a
			// log.
			return fmt.Errorf("the value given for %s is not one this fix accepts. It has to be %s",
				plainName(p), plainShape(p))
		}
	}
	for name := range params {
		if !declaresParam(a, name) {
			return fmt.Errorf("this fix was given a value called %q that it does not use", name)
		}
	}
	return nil
}

func plainName(p Param) string {
	if p.Why != "" {
		return p.Why
	}
	return p.Name
}

func plainShape(p Param) string {
	if p.Why != "" {
		return p.Why
	}
	return "of the form " + p.Allow.String()
}

// fillText puts the values into a sentence written for a person.
//
// A missing value is left as it was rather than blanked, so the summary on the
// approval screen never quietly loses the word that said what would be touched.
func fillText(text string, params map[string]string) string {
	return paramRef.ReplaceAllStringFunc(text, func(match string) string {
		value, given := params[paramRef.FindStringSubmatch(match)[1]]
		if !given || strings.TrimSpace(value) == "" {
			return match
		}
		return value
	})
}
