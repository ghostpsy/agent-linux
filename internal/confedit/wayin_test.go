//go:build linux

package confedit

import (
	"os"
	"strings"
	"testing"
)

// The lock-out this code exists to prevent, stated as a test.
//
// A Rocky 9 cloud machine has exactly one account with a key: root. Refusing root
// logins there locks everybody out, and nothing about the machine looks wrong
// afterwards — sshd is running and the port accepts every connection before
// refusing every login.
func TestRefusingRootLoginsNeedsSomebodyElseWithAKey(t *testing.T) {
	cloudImage := Access{AccountsWithKeys: 1, NonRootAccountsWithKeys: 0}

	allowed, why := cloudImage.AllowsChange(WayInOtherAccountKey)

	if allowed {
		t.Fatal("root is the only account with a key, so refusing root logins locks everybody out")
	}
	if !strings.Contains(why, "root is the only account") {
		t.Fatalf("expected the reason to say why, got %q", why)
	}
}

func TestRefusingRootLoginsIsFineWhenSomebodyElseHasAKey(t *testing.T) {
	proper := Access{AccountsWithKeys: 2, NonRootAccountsWithKeys: 1}

	if allowed, why := proper.AllowsChange(WayInOtherAccountKey); !allowed {
		t.Fatalf("expected this to be allowed, got %q", why)
	}
}

// Turning off password logins on a machine nobody has a key for is the same
// failure from the other direction.
func TestTurningOffPasswordLoginsNeedsAtLeastOneKey(t *testing.T) {
	noKeys := Access{}

	allowed, why := noKeys.AllowsChange(WayInAnyKey)

	if allowed {
		t.Fatal("with no key anywhere, turning off password logins leaves no way in")
	}
	if !strings.Contains(why, "no way to log in at all") {
		t.Fatalf("expected the reason to say what to do about it, got %q", why)
	}
}

func TestTurningOffPasswordLoginsIsFineWhenRootHasAKey(t *testing.T) {
	// Root's own key counts here: the operator who reaches this machine as root
	// with a key keeps working. That is exactly the cloud-image case.
	rootOnly := Access{AccountsWithKeys: 1, NonRootAccountsWithKeys: 0}

	if allowed, why := rootOnly.AllowsChange(WayInAnyKey); !allowed {
		t.Fatalf("expected this to be allowed, got %q", why)
	}
}

func TestASettingThatCannotLockAnybodyOutNeedsNothing(t *testing.T) {
	if allowed, _ := (Access{}).AllowsChange(WayInNothing); !allowed {
		t.Fatal("X11 forwarding has nothing to do with logging in")
	}
}

// An unknown requirement must refuse, not wave the change through. This is the
// direction to fail in.
func TestAnUnknownRequirementRefuses(t *testing.T) {
	if allowed, _ := (Access{AccountsWithKeys: 9}).AllowsChange(WayIn("something-new")); allowed {
		t.Fatal("a requirement ghostpsy does not understand must stop the change")
	}
}

// A file with only a comment in it is not a way in. Counting it would let the
// change through on exactly the machine this protects.
func TestAnAuthorizedKeysFileWithOnlyACommentIsNotAWayIn(t *testing.T) {
	home := t.TempDir()
	writeKeys(t, home, "# put your key here\n\n")

	if hasAnyKey(home) {
		t.Fatal("a comment is not a key")
	}

	writeKeys(t, home, "# mine\nssh-ed25519 AAAAC3Nza real@key\n")
	if !hasAnyKey(home) {
		t.Fatal("a real key after a comment is still a key")
	}
}

// A system account cannot be a way in, however many keys it has.
func TestAnAccountThatCannotLogInDoesNotCount(t *testing.T) {
	for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""} {
		if canLogIn(shell) {
			t.Errorf("%q is not a shell somebody can log in with", shell)
		}
	}
	for _, shell := range []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh"} {
		if !canLogIn(shell) {
			t.Errorf("%q is a real shell", shell)
		}
	}
}

func TestPasswdLinesAreReadTheWayTheKernelWritesThem(t *testing.T) {
	name, home, shell, ok := passwdFields("root:x:0:0:root:/root:/bin/bash")
	if !ok || name != "root" || home != "/root" || shell != "/bin/bash" {
		t.Fatalf("got %q %q %q ok=%v", name, home, shell, ok)
	}
	if _, _, _, ok := passwdFields("nonsense"); ok {
		t.Fatal("a line that is not a passwd entry must be skipped")
	}
}

func writeKeys(t *testing.T, home, content string) {
	t.Helper()
	dir := home + "/.ssh"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/authorized_keys", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
