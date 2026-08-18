//go:build linux

// Package confedit changes one declared setting in one declared config file.
//
// A fix that hardens SSH or switches on automatic updates has to edit a file, and
// no sudo rule can express "may write this one line of this one file". So the
// same pattern the agent already uses for reading /etc/shadow is used here: the
// grant names our own signed binary, and the list of what may be touched lives
// in typed Go where it can be read and tested.
//
// The list is deliberately tiny. Every entry is a setting we are confident about
// on a server we have never seen, and nothing else can be reached — not a file
// path from the cloud, not a directive name, not a value outside the shape below.
package confedit

import (
	"fmt"
	"slices"
	"sort"
)

// Style is how a file writes its settings.
type Style string

const (
	// StyleSSH is `Directive value`, with # for comments. sshd_config.
	StyleSSH Style = "ssh"

	// StyleAPTConf is `Name::Path "value";`. apt.conf.d files.
	StyleAPTConf Style = "apt.conf"
)

// Setting is one thing this agent is allowed to change.
type Setting struct {
	// Key is how the service names it. It never names a file path.
	Key string

	File      string
	Directive string
	Style     Style

	// Allow is every value accepted, written out one by one.
	//
	// It is a list rather than a pattern because three other things are generated
	// from it and a pattern cannot be enumerated: the sudo grant needs one line
	// per value, the shipped drop-in files need one file per value, and the app
	// needs the values it may offer. `^[3-6]$` cannot produce those; {"3","4",
	// "5","6"} can.
	//
	// Empty means there is no value of this setting ghostpsy sets itself. The entry
	// exists to explain the change, not to make it — see Dangerous.
	Allow []string

	// Dangerous is the values ghostpsy explains but never sets, by value.
	//
	// A change can be worth making and still be one we must not make: only the
	// person who knows the server can judge whether it survives. Leaving such a
	// change out entirely is not caution, it is unhelpfulness — they will do it
	// from memory instead. See danger.go.
	Dangerous map[string]DangerousChange

	// Units are the services that must be reloaded for a change to this file to
	// take effect, most specific name first.
	//
	// This is where the unit name comes from, instead of from the distribution.
	// internal/action/catalog.go used to pick `ssh` or `sshd` by looking for
	// /etc/debian_version or /etc/redhat-release — a guess about the machine when the
	// machine could simply be asked which unit it has.
	//
	// Empty is a real answer: apt re-reads apt.conf.d on every periodic run, so
	// nothing has to be reloaded, and naming a unit would grant a restart nobody needs.
	Units []string

	// NeedsAWayIn says what must still be true for this change to be safe.
	//
	// Closing a door is not automatically safe. Turning off password logins on a
	// server nobody has a key for locks everybody out, and the machine then looks
	// perfectly healthy from outside: sshd is up, the port accepts the connection,
	// and every login is refused. Found by locking myself out of a real machine.
	NeedsAWayIn WayIn

	// Why says in plain words what this setting does and why changing it is
	// safe. It reaches the approval screen.
	Why string
}

// WayIn is what has to remain possible after a change.
type WayIn string

const (
	// WayInNothing means this setting cannot affect anybody's ability to log in.
	WayInNothing WayIn = ""

	// WayInAnyKey means at least one account must have an SSH key, or turning off
	// password logins leaves no way in at all.
	WayInAnyKey WayIn = "any_key"

	// WayInOtherAccountKey means some account *other than root* must have a key.
	// Needed before root logins are refused outright.
	WayInOtherAccountKey WayIn = "other_account_key"
)

// settings is every change this agent can make to a config file.
var settings = map[string]Setting{}

func declare(s Setting) {
	if _, exists := settings[s.Key]; exists {
		panic("confedit: duplicate setting " + s.Key)
	}
	if s.File == "" || s.Directive == "" || s.Why == "" {
		panic("confedit: setting " + s.Key + " is not fully declared")
	}
	// A setting that can neither be set nor explained has no purpose, and would
	// show up on screen as a choice that does nothing.
	if len(s.Allow) == 0 && len(s.Dangerous) == 0 {
		panic("confedit: setting " + s.Key + " can neither be set nor explained")
	}
	settings[s.Key] = s
}

// Lookup returns the declared setting, or false.
func Lookup(key string) (Setting, bool) {
	s, ok := settings[key]
	return s, ok
}

// All returns every declared setting, in a stable order, so `ghostpsy actions`
// can print the whole list of what this agent may change.
func All() []Setting {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]Setting, 0, len(keys))
	for _, key := range keys {
		out = append(out, settings[key])
	}
	return out
}

// Check returns the setting for key, if the value is one it accepts.
func Check(key, value string) (Setting, error) {
	s, known := Lookup(key)
	if !known {
		return Setting{}, fmt.Errorf("%q is not a setting ghostpsy is allowed to change", key)
	}

	// The dangerous list first. A value on it gets the advice rather than a plain
	// refusal, and a caller can pass that straight on to the person who asked.
	if danger, listed := s.Dangerous[value]; listed {
		danger.Setting = s.Directive
		danger.Value = value
		return Setting{}, &danger
	}

	if !slices.Contains(s.Allow, value) {
		return Setting{}, fmt.Errorf(
			"ghostpsy will not set %s to that value. %s", s.Directive, s.Why)
	}
	return s, nil
}

// sortedDangerValues lists a setting's dangerous values in a stable order, so the
// printed list and the API's answer do not shuffle between calls.
func sortedDangerValues(s Setting) []string {
	values := make([]string, 0, len(s.Dangerous))
	for value := range s.Dangerous {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// sshUnits is what the SSH server is called, most specific first.
//
// Debian calls it ssh, the RHEL family calls it sshd, and some machines have both
// names for the same thing. Both are declared and the agent uses whichever is
// actually there, so nothing has to know which distribution this is.
var sshUnits = []string{"sshd", "ssh"}

func init() {
	// SSH. Every value below is one that closes a door; none of them can open
	// one. That is the rule for this list: a setting whose allowed values could
	// weaken a server does not belong here, whoever asks for it.
	//
	// Closing a door is not automatically safe, though. Two of these can close the
	// door on the operator, and the action that uses them asks the machine whether
	// anybody would still be able to get in — see NeedsAWayIn below.

	// Deliberately not `no` yet. That locks out every account on a machine where
	// root is the only one with a key — which is nearly every cloud image — and the
	// machine then looks perfectly healthy: sshd is up, port 22 accepts the
	// connection, and refuses every login. Found by locking myself out of a real
	// Rocky 9 machine.
	//
	// `prohibit-password` keeps key logins, so it is safe as long as somebody has
	// a key — which is what the action checks before it runs.
	declare(Setting{
		Key:         "ssh.permit_root_login",
		File:        sshdConfigPath,
		Directive:   "PermitRootLogin",
		Style:       StyleSSH,
		Units:       sshUnits,
		Allow:       []string{"prohibit-password"},
		NeedsAWayIn: WayInAnyKey,
		Why: "It stops somebody logging in as root with a password, and keeps key " +
			"logins working. Only 'prohibit-password' can be set here.",
		Dangerous: map[string]DangerousChange{
			"no": {
				Risk: "on a server where root is the only account with an SSH key, this " +
					"refuses every login and leaves nobody able to get in. The server looks " +
					"perfectly healthy afterwards: it accepts the connection and then " +
					"refuses the login, so the problem only shows up when somebody needs to " +
					"log in. Only you can tell whether this server has another way in",
				CheckFirst: "open a second SSH session as a non-root user now, and keep it " +
					"open while you do this. If you cannot, do not do this",
				Commands: []string{
					"# 1. Keep a second session open before you start.",
					"cp /etc/ssh/sshd_config /etc/ssh/sshd_config.before-hardening",
					"",
					"# 2. Make the change.",
					"sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
					"grep -q '^PermitRootLogin no' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
					"",
					"# 3. Check it before anything reads it. Stop here if this fails.",
					"sshd -t",
					"",
					"# 4. Apply it, then log in again from a NEW terminal before closing this one.",
					"systemctl reload sshd || systemctl reload ssh",
					"sshd -T | grep -i permitrootlogin",
					"",
					"# If you are locked out, the way back is:",
					"#   cp /etc/ssh/sshd_config.before-hardening /etc/ssh/sshd_config && systemctl reload sshd",
				},
			},
		},
	})
	// Advice only. ghostpsy never turns password logins off itself.
	//
	// It can prove that somebody has a key. It cannot prove that the key belongs to
	// the person about to be shut out, and on a hand-built server the operator may
	// be reaching it with a password right this minute. That is not a judgement to
	// make on somebody else's server, so the answer is the commands and the check.
	declare(Setting{
		Key:       "ssh.password_authentication",
		File:      sshdConfigPath,
		Directive: "PasswordAuthentication",
		Style:     StyleSSH,
		Units:     sshUnits,
		Why: "It turns off password logins, leaving keys only. ghostpsy never makes " +
			"this change itself: only you can be sure your own key works, and getting " +
			"it wrong locks you out of your own server.",
		Dangerous: map[string]DangerousChange{
			"no": {
				Risk: "if the key you log in with does not work, or you have been using a " +
					"password without realising, this shuts you out of your own server and " +
					"there is no way back in over the network. ghostpsy can see that some " +
					"account has a key; it cannot see whether that key is yours",
				CheckFirst: "prove your key works before you change anything: from your own " +
					"machine, run `ssh -o PasswordAuthentication=no you@this-server true`. If " +
					"that fails, stop",
				Commands: []string{
					"# 1. Prove your key works, from your own machine, before touching anything:",
					"#    ssh -o PasswordAuthentication=no you@this-server true",
					"# Keep that session open while you do the rest.",
					"",
					"# 2. On a cloud image a drop-in file usually overrides sshd_config, so the",
					"#    edit below would take and the setting would not. Look first:",
					"grep -rniH passwordauthentication /etc/ssh/sshd_config.d/ 2>/dev/null",
					"#    Edit whichever file you find there instead of the one below.",
					"",
					"cp /etc/ssh/sshd_config /etc/ssh/sshd_config.before-hardening",
					"",
					"# 3. Make the change.",
					"sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
					"grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config",
					"",
					"# 4. Check it before anything reads it. Stop here if this fails.",
					"sshd -t",
					"",
					"# 5. Apply it, then confirm what sshd actually believes.",
					"systemctl reload sshd || systemctl reload ssh",
					"sshd -T | grep -i passwordauthentication",
					"",
					"# 6. Log in again from a NEW terminal before closing this one.",
					"",
					"# If you are locked out, the way back is:",
					"#   cp /etc/ssh/sshd_config.before-hardening /etc/ssh/sshd_config && systemctl reload sshd",
				},
			},
		},
	})
	declare(Setting{
		Key:       "ssh.permit_empty_passwords",
		File:      sshdConfigPath,
		Directive: "PermitEmptyPasswords",
		Style:     StyleSSH,
		Units:     sshUnits,
		Allow:     []string{"no"},
		Why:       "It refuses accounts with no password at all. Only 'no' can be set here.",
	})
	declare(Setting{
		Key:       "ssh.x11_forwarding",
		File:      sshdConfigPath,
		Directive: "X11Forwarding",
		Style:     StyleSSH,
		Units:     sshUnits,
		Allow:     []string{"no"},
		Why: "It stops SSH forwarding graphical windows, which a server does not " +
			"need. Only 'no' can be set here.",
	})
	declare(Setting{
		Key:       "ssh.max_auth_tries",
		File:      sshdConfigPath,
		Directive: "MaxAuthTries",
		Style:     StyleSSH,
		Units:     sshUnits,
		Allow:     []string{"3", "4", "5", "6"},
		Why: "It limits how many times one connection may guess. Only 3 to 6 can " +
			"be set here, so it can never be raised to something useless.",
	})

	// Automatic security updates on Debian and Ubuntu. Both lines live in the
	// same file, and both are needed: downloading the lists without installing
	// anything does nothing at all.
	declare(Setting{
		Key:       "apt.update_package_lists",
		File:      aptAutoUpgradesPath,
		Directive: "APT::Periodic::Update-Package-Lists",
		Style:     StyleAPTConf,
		Allow:     []string{"1"},
		Why:       "It makes the machine check daily for new packages. Only '1' can be set here.",
	})
	declare(Setting{
		Key:       "apt.unattended_upgrade",
		File:      aptAutoUpgradesPath,
		Directive: "APT::Periodic::Unattended-Upgrade",
		Style:     StyleAPTConf,
		Allow:     []string{"1"},
		Why: "It makes the machine install security updates on its own. Only '1' " +
			"can be set here. This is the one change that stops future problems " +
			"appearing rather than fixing one that already has.",
	})
}

const (
	sshdConfigPath      = "/etc/ssh/sshd_config"
	aptAutoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"
)
