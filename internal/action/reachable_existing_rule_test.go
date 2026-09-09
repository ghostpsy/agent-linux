//go:build linux

package action

import (
	"strings"
	"testing"
)

// whatUfwSaysWhenTheRuleIsAlreadyThere is the real output, taken from an Ubuntu
// 24.04 machine where port 22 was already allowed:
//
//	$ ufw show added
//	Added user rules (see 'ufw status' for running firewall):
//	ufw allow 22/tcp
//	$ ufw --dry-run allow 22/tcp
//	Skipping adding existing rule
//	Skipping adding existing rule (v6)
const whatUfwSaysWhenTheRuleIsAlreadyThere = `Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp
Skipping adding existing rule
Skipping adding existing rule (v6)
`

// TestAPortAlreadyAllowedDoesNotBlockTheChange is the refusal this fixes.
//
// ghostpsy said: "You are connected on port 22, and the rules this change would
// install do not mention port 22. Switching the firewall on would cut you off
// from this machine."
//
// It would not have. Port 22 was already allowed, which is why ufw had no rule
// left to install and printed none. The check read "no rules mention 22" as "22
// will be closed", and refused the change on the machine that was in the safest
// possible state for it.
func TestAPortAlreadyAllowedDoesNotBlockTheChange(t *testing.T) {
	if !allowedByExistingRule(whatUfwSaysWhenTheRuleIsAlreadyThere, 22) {
		t.Fatal("an existing `ufw allow 22/tcp` was not read as allowing port 22")
	}
}

// A rule that names the port and blocks it must never read as reassurance.
func TestADenyRuleIsNotAnAllow(t *testing.T) {
	denied := `Added user rules (see 'ufw status' for running firewall):
ufw deny 22/tcp
ufw allow 80/tcp
`
	if allowedByExistingRule(denied, 22) {
		t.Error("a `ufw deny 22/tcp` was read as allowing port 22")
	}
	if !allowedByExistingRule(denied, 80) {
		t.Error("a `ufw allow 80/tcp` on the next line was missed")
	}
	if allowedByExistingRule(`ufw reject 2222/tcp`, 2222) {
		t.Error("a reject rule was read as an allow")
	}
}

func TestAPortNobodyAllowedIsStillReported(t *testing.T) {
	rules := `Added user rules (see 'ufw status' for running firewall):
ufw allow 80/tcp
`
	if allowedByExistingRule(rules, 22) {
		t.Fatal("port 22 was reported as allowed by a rule for port 80")
	}
}

// The digit-boundary rule matters here as much as anywhere: an operator on 2222
// must not be reassured by a rule for 22.
func TestAnAllowForOnePortIsNotAnAllowForAnotherThatContainsIt(t *testing.T) {
	if allowedByExistingRule(`ufw allow 22/tcp`, 2222) {
		t.Error("a rule for 22 was read as covering 2222")
	}
	if allowedByExistingRule(`ufw allow 2222/tcp`, 22) {
		t.Error("a rule for 2222 was read as covering 22")
	}
}

// The rules ufw lists for a specific address still name the port.
func TestARuleScopedToAnAddressStillCountsAsAnAllow(t *testing.T) {
	rules := `Added user rules (see 'ufw status' for running firewall):
ufw allow from 10.0.0.0/8 to any port 22 proto tcp
`
	if !allowedByExistingRule(rules, 22) {
		t.Fatal("an allow scoped to an address was not read as allowing the port")
	}
}

// The state that produced "ERROR: problem running".
//
// ufw keeps two answers to "am I on": ENABLED in /etc/ufw/ufw.conf, and whether
// its chains are in the kernel. Reproduced on Ubuntu 24.04 by setting
// ENABLED=yes with no chains loaded:
//
//	$ sudo ufw allow 22/tcp
//	ERROR: problem running
//	exit=1
//
// ufw was trying to flush chains that were not there. The fix switches ufw off
// first to make its record honest — which is only safe while it really is off,
// and that is what this check is for.
func TestSwitchingOffIsRefusedWhenTheFirewallIsWorking(t *testing.T) {
	before := []CommandRun{{Stdout: "Status: active\nTo    Action   From\n22/tcp ALLOW Anywhere"}}

	run, ok := firewallIsStillOff("make sure it is still off", before)
	if ok {
		t.Fatal("agreed to switch off a firewall that was enforcing")
	}
	if !strings.Contains(run.Stderr, "on now") {
		t.Errorf("the reason does not say the firewall is on: %q", run.Stderr)
	}
}

func TestSwitchingOffIsAllowedWhenNothingIsEnforced(t *testing.T) {
	before := []CommandRun{{Stdout: "Status: inactive"}}

	run, ok := firewallIsStillOff("make sure it is still off", before)
	if !ok {
		t.Fatalf("refused on an inactive firewall: %q", run.Stderr)
	}
	if !strings.Contains(run.Stdout, "takes no protection away") {
		t.Errorf("the reason does not explain why it is safe: %q", run.Stdout)
	}
}

// Not knowing is a refusal, not a shrug. Carrying on would mean switching a
// firewall off without knowing whether it was protecting anything.
func TestNotKnowingTheFirewallStateIsARefusal(t *testing.T) {
	for _, before := range [][]CommandRun{
		nil,
		{{Stdout: ""}},
		{{Stderr: "ufw: command not found"}},
	} {
		if _, ok := firewallIsStillOff("why", before); ok {
			t.Errorf("carried on without knowing the firewall state: %+v", before)
		}
	}
}

// The last status wins, because the run phase reads its own fresh one rather
// than a stale line from the preview.
func TestTheMostRecentStatusIsTheOneRead(t *testing.T) {
	before := []CommandRun{
		{Stdout: "Status: inactive"},
		{Stdout: "Status: active"},
	}
	if _, ok := firewallIsStillOff("why", before); ok {
		t.Fatal("read an older status and missed that the firewall is now on")
	}
}
