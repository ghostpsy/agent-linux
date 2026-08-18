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
			if s.Allow != nil && s.Allow.MatchString(value) {
				t.Errorf("%s=%s is both allowed and dangerous, which cannot both be true",
					s.Key, value)
			}
		}
	}
}

// A setting with nothing safe in it at all.
//
// Turning off password logins is worth doing and is not ours to do: the operator
// may be reaching this server with a password right now, and we cannot tell. Its
// only value was `no`, so moving that to the dangerous list leaves the setting
// entirely advisory — a shape this catalogue did not have before.
func TestASettingCanBeAdviceOnly(t *testing.T) {
	s, known := Lookup("ssh.password_authentication")
	if !known {
		t.Fatal("the setting has to stay on the list, or the app cannot offer the advice")
	}
	if s.Allow != nil {
		t.Fatal("there is no value of this setting ghostpsy sets itself")
	}
	if len(s.Dangerous) == 0 {
		t.Fatal("a setting with nothing safe in it must at least explain how to do it by hand")
	}
}

func TestTurningOffPasswordLoginsIsHandedOverRatherThanDone(t *testing.T) {
	_, err := Check("ssh.password_authentication", "no")

	var danger *DangerousChange
	if !errors.As(err, &danger) {
		t.Fatalf("expected this to be handed over with commands, got: %v", err)
	}
	joined := strings.Join(danger.Commands, "\n")
	for _, want := range []string{
		"PasswordAuthentication no",
		"sshd -t",
		// The trap that makes this fail silently on a cloud image: a drop-in file
		// overrides sshd_config, so the edit takes and the setting does not.
		"sshd_config.d",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected the commands to mention %q, got:\n%s", want, joined)
		}
	}
}

// An advice-only setting still refuses anything not on its list, and without
// pretending to help. Explaining how to switch password logions back on would be
// explaining how to weaken the server.
func TestAnAdviceOnlySettingRefusesEverythingElsePlainly(t *testing.T) {
	_, err := Check("ssh.password_authentication", "yes")

	if err == nil {
		t.Fatal("'yes' opens a door and must be refused")
	}
	var danger *DangerousChange
	if errors.As(err, &danger) {
		t.Fatal("we do not explain how to make a server weaker")
	}
}

// The catalogue must not contain a setting that can neither be set nor explained.
// That is an entry with no purpose, and it would show up as a dead choice on screen.
func TestEverySettingCanEitherBeSetOrExplained(t *testing.T) {
	for _, s := range All() {
		if s.Allow == nil && len(s.Dangerous) == 0 {
			t.Errorf("%s can neither be set nor explained, so it should not be on the list", s.Key)
		}
	}
}

// Turning off password logins is now advice, so nothing on the automatic path may
// still be relying on a way-in rule for it. A rule that can never fire is dead
// configuration, and dead configuration is where a wrong assumption hides.
func TestNoAdviceOnlySettingStillDeclaresAWayInRule(t *testing.T) {
	for _, s := range All() {
		if s.Allow == nil && s.NeedsAWayIn != WayInNothing {
			t.Errorf("%s is advice only, so its way-in rule can never fire", s.Key)
		}
	}
}
