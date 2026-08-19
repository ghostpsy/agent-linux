//go:build linux

package confedit

import (
	"strings"
	"testing"
)

// A drop-in file only works if sshd reads it before anything that contradicts it.
//
// sshd keeps the FIRST value it sees for a keyword. So the question is not "is there
// an Include line" but "does the Include come before any line that already sets this".
// Measured on debian-13: Include is on line 12 and `X11Forwarding yes` on line 92, and
// a drop-in did change the effective value. Getting this backwards would mean writing
// a file, reporting success, and changing nothing.

const debianLikeConfig = `# Package generated configuration file
Include /etc/ssh/sshd_config.d/*.conf

#MaxAuthTries 6
PasswordAuthentication no
X11Forwarding yes
`

func TestADropInWinsWhenTheIncludeComesFirst(t *testing.T) {
	s, _ := Lookup("ssh.x11_forwarding")
	wins, why := DropInWins(s, debianLikeConfig)
	if !wins {
		t.Fatalf("a live line after the Include should still lose to a drop-in: %s", why)
	}
}

func TestACommentedLineDoesNotStopADropIn(t *testing.T) {
	s, _ := Lookup("ssh.max_auth_tries")
	if wins, why := DropInWins(s, debianLikeConfig); !wins {
		t.Fatalf("a commented default is not a setting: %s", why)
	}
}

func TestADropInLosesToALineAboveTheInclude(t *testing.T) {
	config := "MaxAuthTries 10\nInclude /etc/ssh/sshd_config.d/*.conf\n"
	s, _ := Lookup("ssh.max_auth_tries")

	wins, why := DropInWins(s, config)
	if wins {
		t.Fatal("a drop-in cannot win against a line sshd reads first")
	}
	// The reason has to name the line, because the person's next move is to look at it.
	if !strings.Contains(why, "line 1") {
		t.Errorf("the reason does not say where the line is: %s", why)
	}
	if !strings.Contains(why, "MaxAuthTries") {
		t.Errorf("the reason does not name the setting: %s", why)
	}
}

func TestADropInLosesWhenThereIsNoIncludeAtAll(t *testing.T) {
	config := "PasswordAuthentication no\n"
	s, _ := Lookup("ssh.max_auth_tries")

	wins, why := DropInWins(s, config)
	if wins {
		t.Fatal("without an Include line nothing in sshd_config.d is read")
	}
	if !strings.Contains(why, "Include") {
		t.Errorf("the reason does not mention the missing Include: %s", why)
	}
}

// A commented-out Include is not an Include. sshd would read nothing.
func TestACommentedIncludeDoesNotCount(t *testing.T) {
	config := "#Include /etc/ssh/sshd_config.d/*.conf\nMaxAuthTries 10\n"
	s, _ := Lookup("ssh.max_auth_tries")
	if wins, _ := DropInWins(s, config); wins {
		t.Fatal("a commented Include was treated as if sshd read the directory")
	}
}

// apt has no Include and needs none: apt.conf.d is read whole, and the last file
// wins. Asking this question about an apt setting must not refuse it.
func TestAnAPTSettingAlwaysWins(t *testing.T) {
	s, _ := Lookup("apt.unattended_upgrade")
	if wins, why := DropInWins(s, ""); !wins {
		t.Fatalf("apt.conf.d needs no Include line: %s", why)
	}
}
