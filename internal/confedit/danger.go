//go:build linux

package confedit

import (
	"fmt"
	"strings"
)

// Some changes ghostpsy must never make, and should still help with.
//
// The obvious way to handle a change that is too risky to automate is to leave it
// out. That is not help: the person still wants it, and leaving it out means they
// go and do it from memory, at midnight, without the check that would have saved
// them.
//
// So there is a third answer between "we will do it" and "no". A dangerous change
// is declared with the same care as one we carry out — what could go wrong, what to
// confirm first, and the exact commands to run — and ghostpsy refuses to run it
// while handing all of that over.
//
// `PermitRootLogin no` is the first entry. It is genuinely worth doing on a server
// with a second account, and on a cloud image where root holds the only key it
// locks everybody out, leaving a machine that looks perfectly healthy: sshd up,
// port 22 accepting every connection, refusing every login. Only the person who
// knows the server can judge which of those they have. That judgement is exactly
// what we cannot make for them, and exactly why this category exists.

// DangerousChange is a change ghostpsy will explain but never make.
type DangerousChange struct {
	// Setting and Value name the change, in the same words the safe path uses.
	Setting string
	Value   string

	// Risk says what could go wrong, in plain words. Not a warning label — the
	// specific bad outcome, so the reader can tell whether it applies to them.
	Risk string

	// CheckFirst is what to confirm before running the commands. The one step
	// that turns a dangerous change into a safe one.
	CheckFirst string

	// Commands are what to run, ready to paste. Advice somebody has to translate
	// is advice they will get wrong.
	Commands []string
}

// Error makes a dangerous change a refusal a caller can simply pass on.
//
// The words are the whole message: a person reading "ghostpsy will not do this"
// with nothing after it learns only that we are unhelpful.
func (d *DangerousChange) Error() string {
	return fmt.Sprintf(
		"ghostpsy will not set %s to %q, because %s. Check first: %s. To do it yourself:\n%s",
		d.Setting, d.Value, d.Risk, d.CheckFirst, strings.Join(d.Commands, "\n"))
}

// Script is the commands as one block, ready to copy.
func (d *DangerousChange) Script() string {
	return strings.Join(d.Commands, "\n")
}

// dangerousChanges is every change on the dangerous list, in a stable order.
//
// It is what `ghostpsy actions` prints under "ghostpsy will never do these", and
// what the service hands the app so a person is told before they ask rather than
// after.
func dangerousChanges() []DangerousChange {
	var out []DangerousChange
	for _, s := range All() {
		for _, value := range sortedDangerValues(s) {
			danger := s.Dangerous[value]
			danger.Setting = s.Directive
			danger.Value = value
			out = append(out, danger)
		}
	}
	return out
}

// Dangerous returns every declared dangerous change.
func Dangerous() []DangerousChange { return dangerousChanges() }
