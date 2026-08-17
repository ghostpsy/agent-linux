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

func TestSetReplacesTheLineThatIsAlreadyThere(t *testing.T) {
	before := "Port 22\nPermitRootLogin yes\nX11Forwarding no\n"

	after, changed := Set(sshSetting(t), before, "no")

	if !changed {
		t.Fatal("expected the file to change")
	}
	if !strings.Contains(after, "PermitRootLogin no\n") {
		t.Fatalf("expected the setting to be replaced, got:\n%s", after)
	}
	if strings.Contains(after, "PermitRootLogin yes") {
		t.Fatalf("expected the old value to be gone, got:\n%s", after)
	}
	if !strings.Contains(after, "Port 22") || !strings.Contains(after, "X11Forwarding no") {
		t.Fatalf("expected every other line to be left alone, got:\n%s", after)
	}
}

// The default in sshd_config is usually written as a comment. Editing the comment
// would change nothing, and adding a second line below it would leave the file
// with two answers to the same question.
func TestSetAddsTheSettingWhenOnlyACommentedDefaultIsThere(t *testing.T) {
	before := "#PermitRootLogin prohibit-password\nPort 22\n"

	after, changed := Set(sshSetting(t), before, "no")

	if !changed {
		t.Fatal("expected the file to change")
	}
	if strings.Count(after, "\nPermitRootLogin ") != 1 && !strings.HasPrefix(after, "PermitRootLogin ") {
		t.Fatalf("expected exactly one live PermitRootLogin line, got:\n%s", after)
	}
	if !strings.Contains(after, "#PermitRootLogin prohibit-password") {
		t.Fatalf("expected the commented default to be left as a record, got:\n%s", after)
	}
}

func TestSetAppendsWhenTheSettingIsAbsent(t *testing.T) {
	before := "Port 22\n"

	after, changed := Set(sshSetting(t), before, "no")

	if !changed || !strings.Contains(after, "PermitRootLogin no") {
		t.Fatalf("expected the setting to be added, got:\n%s", after)
	}
	if !strings.HasSuffix(after, "\n") {
		t.Fatalf("expected the file to still end in a newline, got %q", after)
	}
}

// sshd uses the first occurrence of a keyword and ignores the rest. A fix that
// edited the last one would look right in the file and change nothing at all.
func TestSetChangesTheFirstOccurrenceBecauseThatIsTheOneSshdUses(t *testing.T) {
	before := "PermitRootLogin yes\nPort 22\nPermitRootLogin yes\n"

	after, _ := Set(sshSetting(t), before, "no")

	lines := strings.Split(strings.TrimRight(after, "\n"), "\n")
	if lines[0] != "PermitRootLogin no" {
		t.Fatalf("expected the first occurrence to be the one changed, got:\n%s", after)
	}
}

func TestSetIsAwareThatSshKeywordsAreNotCaseSensitive(t *testing.T) {
	before := "permitrootlogin yes\n"

	after, changed := Set(sshSetting(t), before, "no")

	if !changed {
		t.Fatal("expected a differently cased keyword to be recognised")
	}
	if strings.Contains(strings.ToLower(after), "permitrootlogin yes") {
		t.Fatalf("expected the old value to be gone, got:\n%s", after)
	}
}

func TestSetReportsNoChangeWhenTheValueIsAlreadyRight(t *testing.T) {
	before := "PermitRootLogin no\n"

	after, changed := Set(sshSetting(t), before, "no")

	if changed {
		t.Fatal("expected no change when the setting already has that value")
	}
	if after != before {
		t.Fatalf("expected the file to be untouched, got:\n%s", after)
	}
}

func aptSetting(t *testing.T) Setting {
	t.Helper()
	s, ok := Lookup("apt.unattended_upgrade")
	if !ok {
		t.Fatal("expected apt.unattended_upgrade to be a declared setting")
	}
	return s
}

func TestSetWritesAptStyleWithQuotesAndASemicolon(t *testing.T) {
	after, changed := Set(aptSetting(t), "", "1")

	if !changed {
		t.Fatal("expected the setting to be added to an empty file")
	}
	want := `APT::Periodic::Unattended-Upgrade "1";`
	if !strings.Contains(after, want) {
		t.Fatalf("expected %q, got:\n%s", want, after)
	}
}

func TestSetReplacesAnAptSettingThatIsAlreadyThere(t *testing.T) {
	before := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"

	after, changed := Set(aptSetting(t), before, "1")

	if !changed {
		t.Fatal("expected the file to change")
	}
	if strings.Contains(after, `Unattended-Upgrade "0"`) {
		t.Fatalf("expected the old value to be gone, got:\n%s", after)
	}
	if !strings.Contains(after, `Update-Package-Lists "1"`) {
		t.Fatalf("expected the other setting to be left alone, got:\n%s", after)
	}
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

// The refusal has to explain itself. "Not allowed" without a reason reads like a
// bug in ghostpsy rather than a deliberate protection.
func TestTheRefusalExplainsWhyRootLoginCannotBeTurnedOffCompletely(t *testing.T) {
	_, err := Check("ssh.permit_root_login", "no")

	if err == nil || !strings.Contains(err.Error(), "prohibit-password") {
		t.Fatalf("expected the refusal to point at the safe value, got: %v", err)
	}
}
