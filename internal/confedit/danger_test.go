//go:build linux

package confedit

import (
	"errors"
	"strings"
	"testing"
)

// Some changes ghostpsy must never make, and should still help with.
//
// `PermitRootLogin no` is the first of them. It is a real hardening step and a
// real lock-out: on a server where root is the only account with a key, it refuses
// everybody, and the machine looks perfectly healthy afterwards. I locked myself
// out of a Rocky 9 machine with it.
//
// Refusing silently would be no help at all. The person still wants the change, and
// they are the only one who can judge whether their server survives it. So the
// answer is not "no" — it is "not by us, and here is exactly how to do it
// yourself, and here is what to check first".

func TestADangerousValueIsRefusedAndExplained(t *testing.T) {
	_, err := Check("ssh.permit_root_login", "no")

	if err == nil {
		t.Fatal("ghostpsy must never set PermitRootLogin to no")
	}

	var danger *DangerousChange
	if !errors.As(err, &danger) {
		t.Fatalf("the refusal has to carry the advice, not just say no: %v", err)
	}
	if danger.Risk == "" {
		t.Error("a dangerous change has to say what could go wrong")
	}
	if len(danger.Commands) == 0 {
		t.Error("a dangerous change has to say how to do it by hand")
	}
	if danger.CheckFirst == "" {
		t.Error("a dangerous change has to say what to check before running it")
	}
}

// The commands have to be the real thing, ready to paste. Advice a person has to
// translate is advice they will get wrong.
func TestTheManualCommandsAreCompleteEnoughToPaste(t *testing.T) {
	_, err := Check("ssh.permit_root_login", "no")
	var danger *DangerousChange
	if !errors.As(err, &danger) {
		t.Fatal("expected a dangerous change")
	}

	joined := strings.Join(danger.Commands, "\n")
	for _, want := range []string{"PermitRootLogin no", "sshd -t", "sshd_config"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected the commands to include %q, got:\n%s", want, joined)
		}
	}
}

// A safe value is still safe. The dangerous list must not swallow the setting.
func TestTheSafeValueOfTheSameSettingStillWorks(t *testing.T) {
	if _, err := Check("ssh.permit_root_login", "prohibit-password"); err != nil {
		t.Fatalf("prohibit-password is the safe value and must stay allowed: %v", err)
	}
}

// A value that is neither allowed nor a known danger is simply refused. It is not
// something we have thought about, so it is not something we advise on.
func TestAnUnknownValueIsStillJustRefused(t *testing.T) {
	_, err := Check("ssh.permit_root_login", "yes")

	if err == nil {
		t.Fatal("'yes' opens a door and must be refused")
	}
	var danger *DangerousChange
	if errors.As(err, &danger) {
		t.Fatal("'yes' is not a change we help with — it makes the server weaker")
	}
}

// Every dangerous change on the list has to be fully described, or the screen has
// nothing useful to show.
func TestEveryDangerousChangeIsFullyDescribed(t *testing.T) {
	for _, s := range All() {
		for value, danger := range s.Dangerous {
			if danger.Risk == "" || danger.CheckFirst == "" || len(danger.Commands) == 0 {
				t.Errorf("%s=%s is on the dangerous list but not fully described", s.Key, value)
			}
			// It must not also be a value we would set ourselves. One or the other.
			if s.Allow.MatchString(value) {
				t.Errorf("%s=%s is both allowed and dangerous, which cannot both be true",
					s.Key, value)
			}
		}
	}
}
