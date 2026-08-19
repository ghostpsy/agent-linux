//go:build linux

package confedit

import (
	"strings"
	"testing"
)

func sshSetting(t *testing.T) Setting {
	t.Helper()
	s, ok := Lookup("ssh.permit_root_login")
	if !ok {
		t.Fatal("expected ssh.permit_root_login to be a declared setting")
	}
	return s
}

func aptSetting(t *testing.T) Setting {
	t.Helper()
	s, ok := Lookup("apt.unattended_upgrade")
	if !ok {
		t.Fatal("expected apt.unattended_upgrade to be a declared setting")
	}
	return s
}

func TestValueReadsWhatIsThere(t *testing.T) {
	if got, found := Value(sshSetting(t), "PermitRootLogin prohibit-password\n"); !found || got != "prohibit-password" {
		t.Fatalf("expected to read prohibit-password, got %q found=%v", got, found)
	}
	if got, found := Value(aptSetting(t), "APT::Periodic::Unattended-Upgrade \"1\";\n"); !found || got != "1" {
		t.Fatalf("expected to read 1, got %q found=%v", got, found)
	}
	if _, found := Value(sshSetting(t), "#PermitRootLogin no\n"); found {
		t.Fatal("expected a commented line not to count as a value")
	}
}

// The list of what may be changed is the whole safety of this package.
func TestCheckRefusesASettingThatIsNotDeclared(t *testing.T) {
	if _, err := Check("ssh.root_password", "hunter2"); err == nil {
		t.Fatal("expected an undeclared setting to be refused")
	}
	if _, err := Check("../../etc/shadow", "x"); err == nil {
		t.Fatal("expected a path pretending to be a key to be refused")
	}
}

// Every declared setting can only be moved in the safe direction. A value that
// would open a door must be impossible to write, not merely unlikely.
func TestCheckRefusesAValueThatWouldWeakenTheServer(t *testing.T) {
	weakening := map[string][]string{
		"ssh.permit_root_login":       {"yes", "YES", "without-password ", "no\nPort 2222"},
		"ssh.password_authentication": {"yes"},
		"ssh.permit_empty_passwords":  {"yes"},
		"ssh.max_auth_tries":          {"0", "99", "1000"},
		"apt.unattended_upgrade":      {"0"},
	}
	for key, values := range weakening {
		for _, value := range values {
			if _, err := Check(key, value); err == nil {
				t.Errorf("expected %s=%q to be refused", key, value)
			}
		}
	}
}

// The lock-out this catalogue exists to make impossible.
//
// Found on a real Rocky 9 machine, by locking myself out of it. On a cloud image
// root is usually the only account with an authorized_keys file, so
// `PermitRootLogin no` means nobody can log in again — and the machine looks
// perfectly healthy from outside: sshd is up, port 22 accepts the connection, and
// then refuses every login. The reachability check passed for exactly that reason.
//
// `prohibit-password` is safe and does most of the work: it stops password logins
// for root and keeps key logins, so an operator who reaches the server with a key
// cannot lose access. `no` is only safe on a machine where somebody else can get
// in, and this agent cannot yet prove that. Until it can, it is not offered.
func TestRootLoginCannotBeTurnedOffCompletelyUntilWeCanProveSomebodyElseCanGetIn(t *testing.T) {
	if _, err := Check("ssh.permit_root_login", "no"); err == nil {
		t.Fatal("'no' locks out every account on a machine where root is the only one. " +
			"It must not be settable until the agent can prove another account can log in.")
	}

	if _, err := Check("ssh.permit_root_login", "prohibit-password"); err != nil {
		t.Fatalf("prohibit-password keeps key logins working, so it must stay allowed: %v", err)
	}
}

// The refusal has to explain itself, and hand over the work.
//
// "Not allowed" without a reason reads like a bug in ghostpsy rather than a
// deliberate protection — and it leaves somebody who still wants the change to do
// it from memory. See danger.go: the answer is "not by us, and here is how".
func TestTheRefusalExplainsItselfAndHandsOverTheCommands(t *testing.T) {
	_, err := Check("ssh.permit_root_login", "no")

	if err == nil {
		t.Fatal("expected 'no' to be refused")
	}
	message := err.Error()
	for _, want := range []string{"only account with an SSH key", "Check first", "sshd -t"} {
		if !strings.Contains(message, want) {
			t.Errorf("expected the refusal to contain %q, got:\n%s", want, message)
		}
	}
}
