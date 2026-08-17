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
	"regexp"
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

	// Allow is the only value accepted, anchored. Deliberately narrow: the point
	// of this catalogue is that a bad value cannot be written, not that we would
	// notice afterwards.
	Allow *regexp.Regexp

	// Why says in plain words what this setting does and why changing it is
	// safe. It reaches the approval screen.
	Why string
}

// settings is every change this agent can make to a config file.
var settings = map[string]Setting{}

func declare(s Setting) {
	if _, exists := settings[s.Key]; exists {
		panic("confedit: duplicate setting " + s.Key)
	}
	if s.Allow == nil || s.File == "" || s.Directive == "" || s.Why == "" {
		panic("confedit: setting " + s.Key + " is not fully declared")
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
	if !s.Allow.MatchString(value) {
		return Setting{}, fmt.Errorf(
			"ghostpsy will not set %s to that value. %s", s.Directive, s.Why)
	}
	return s, nil
}

func init() {
	// SSH. Every value below is one that closes a door; none of them can open
	// one. That is the rule for this list: a setting whose allowed values could
	// weaken a server does not belong here, whoever asks for it.
	declare(Setting{
		Key:       "ssh.permit_root_login",
		File:      sshdConfigPath,
		Directive: "PermitRootLogin",
		Style:     StyleSSH,
		Allow:     regexp.MustCompile(`^(no|prohibit-password)$`),
		Why: "It stops somebody logging in directly as root with a password. " +
			"Only 'no' and 'prohibit-password' can be set here, so this can never " +
			"be used to allow root login.",
	})
	declare(Setting{
		Key:       "ssh.password_authentication",
		File:      sshdConfigPath,
		Directive: "PasswordAuthentication",
		Style:     StyleSSH,
		Allow:     regexp.MustCompile(`^no$`),
		Why: "It turns off password logins, leaving keys only. Only 'no' can be " +
			"set here. Make sure your key works before using this.",
	})
	declare(Setting{
		Key:       "ssh.permit_empty_passwords",
		File:      sshdConfigPath,
		Directive: "PermitEmptyPasswords",
		Style:     StyleSSH,
		Allow:     regexp.MustCompile(`^no$`),
		Why:       "It refuses accounts with no password at all. Only 'no' can be set here.",
	})
	declare(Setting{
		Key:       "ssh.x11_forwarding",
		File:      sshdConfigPath,
		Directive: "X11Forwarding",
		Style:     StyleSSH,
		Allow:     regexp.MustCompile(`^no$`),
		Why: "It stops SSH forwarding graphical windows, which a server does not " +
			"need. Only 'no' can be set here.",
	})
	declare(Setting{
		Key:       "ssh.max_auth_tries",
		File:      sshdConfigPath,
		Directive: "MaxAuthTries",
		Style:     StyleSSH,
		Allow:     regexp.MustCompile(`^[3-6]$`),
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
		Allow:     regexp.MustCompile(`^1$`),
		Why:       "It makes the machine check daily for new packages. Only '1' can be set here.",
	})
	declare(Setting{
		Key:       "apt.unattended_upgrade",
		File:      aptAutoUpgradesPath,
		Directive: "APT::Periodic::Unattended-Upgrade",
		Style:     StyleAPTConf,
		Allow:     regexp.MustCompile(`^1$`),
		Why: "It makes the machine install security updates on its own. Only '1' " +
			"can be set here. This is the one change that stops future problems " +
			"appearing rather than fixing one that already has.",
	})
}

const (
	sshdConfigPath      = "/etc/ssh/sshd_config"
	aptAutoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"
)
