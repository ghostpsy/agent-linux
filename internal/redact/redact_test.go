//go:build linux

package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rules, as they were given, in the order they were given.

func TestAnAccountNameKeepsTwoLettersAndLosesTheRest(t *testing.T) {
	got := Text([]string{"edyan", "deploy"}, "AllowUsers edyan deploy")

	if got != "AllowUsers ed*** de****" {
		t.Errorf("got %q", got)
	}
}

// A name is hidden wherever it appears, not only after a directive we thought of.
// This is the reason the list comes from /etc/passwd rather than from a list of
// directive names: a home directory, a crontab line and a comment all carry it.
func TestAnAccountNameIsHiddenWhereverItAppears(t *testing.T) {
	for _, line := range []string{
		"AuthorizedKeysFile /home/edyan/.ssh/authorized_keys",
		"0 3 * * * /home/edyan/backup.sh",
		"# added by edyan on Tuesday",
	} {
		got := Text([]string{"edyan"}, line)
		if strings.Contains(got, "edyan") {
			t.Errorf("the name survived in %q", got)
		}
		if !strings.Contains(got, "ed***") {
			t.Errorf("expected ed*** in %q", got)
		}
	}
}

// A longer word that happens to contain the name is not the account, and masking
// inside it would produce half-masked words nobody can read.
//
// A dash or a slash is a different matter: `/var/edyan-backups` really is named after
// the person, so the name is covered there. This test was written the other way round
// first, which was wrong — leaving it readable would have sent the name anyway.
func TestTheNameIsMaskedWhereItIsReallyTheNameAndNowhereElse(t *testing.T) {
	got := Text([]string{"edyan"}, "edyanx /var/edyan-backups edyan")

	if got != "edyanx /var/ed***-backups ed***" {
		t.Errorf("got %q", got)
	}
}

func TestRootIsNeverMasked(t *testing.T) {
	line := "install -m 0600 -o root -g root src dest"

	if got := Text([]string{"root", "edyan"}, line); got != line {
		t.Errorf("root has to stay readable, got %q", got)
	}
}

func TestAnSSHKeyLosesItsBodyAndMostOfItsComment(t *testing.T) {
	got := Text(nil, "ssh-rsa abcde test@localhost")

	if got != "ssh-rsa **** tes****" {
		t.Errorf("got %q", got)
	}
}

// A real key is 400 characters. The mask is a fixed four stars, so the length of the
// key does not leak either.
func TestTheMaskDoesNotSayHowLongTheKeyWas(t *testing.T) {
	long := "ssh-ed25519 " + strings.Repeat("A", 400) + " edyan@laptop"

	got := Text(nil, long)

	if strings.Contains(got, "AAAA") {
		t.Errorf("the key body survived: %q", got)
	}
	if strings.Count(got, "*") > 12 {
		t.Errorf("the number of stars follows the key length: %q", got)
	}
}

func TestAnIPv4AddressKeepsItsFirstNumber(t *testing.T) {
	got := Text(nil, "-A INPUT -s 1.2.3.4 -j ACCEPT")

	if got != "-A INPUT -s 1.*.*.* -j ACCEPT" {
		t.Errorf("got %q", got)
	}
}

// The prefix length is what makes a firewall rule readable: /32 is one machine and
// /8 is sixteen million. Hiding it would hide the thing being judged.
func TestTheNetworkSizeIsKept(t *testing.T) {
	got := Text(nil, "10.0.0.0/8 and 192.168.1.7/32")

	if got != "10.*.*.*/8 and 192.*.*.*/32" {
		t.Errorf("got %q", got)
	}
}

// These four are not addresses of anybody. Masking them would destroy the only
// information that matters in a firewall rule: "open to the whole internet".
func TestTheAddressesThatMeanEverywhereAndHereAreKept(t *testing.T) {
	line := "0.0.0.0/0 ::/0 127.0.0.1 ::1"

	if got := Text(nil, line); got != line {
		t.Errorf("got %q", got)
	}
}

func TestAnIPv6AddressKeepsItsFirstGroup(t *testing.T) {
	got := Text(nil, "listenaddress 2001:db8::1")

	if !strings.HasPrefix(got, "listenaddress 2001:") {
		t.Errorf("the first group has to stay, got %q", got)
	}
	if strings.Contains(got, "db8") {
		t.Errorf("the rest of the address survived: %q", got)
	}
}

// Accounts reads the real names off the machine. Below 1000 is a service, not a
// person, and hiding postgres or www-data would remove information without
// protecting anybody.
func TestAccountsTakesThePeopleAndLeavesTheServices(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	body := "root:x:0:0:root:/root:/bin/bash\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
		"postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n" +
		"edyan:x:1000:1000:Emmanuel:/home/edyan:/bin/bash\n" +
		"deploy:x:1001:1001::/home/deploy:/bin/bash\n" +
		"nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\n"
	if err := os.WriteFile(passwd, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	names, err := accountsIn(passwd)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"edyan", "deploy"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", names, want)
	}
}

// nobody is uid 65534 and is not a person. It is above 1000, so the uid rule alone
// lets it through, and masking it would make "owned by nobody" unreadable.
func TestNobodyIsNotAPerson(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwd, []byte("nobody:x:65534:65534::/:/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	names, err := accountsIn(passwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Errorf("got %v", names)
	}
}

// A machine with no /etc/passwd is a broken machine, and guessing "there are no
// accounts" would send everything unmasked. An error is the only safe answer.
func TestAMissingPasswdIsAnError(t *testing.T) {
	if _, err := accountsIn(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected an error rather than an empty list")
	}
}
