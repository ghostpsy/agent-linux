//go:build linux

// Package redact hides personal data in command output, on the machine, before any
// of it is sent.
//
// The reason it exists: a fix reports the real output of the real commands it ran, and
// those commands print a customer's SSH configuration and everything their server
// believes. That output carries account names, public keys and addresses. Sending it
// raw would mean the honesty of the report is paid for with somebody's data.
//
// Masking happens here rather than in the cloud, so the data never leaves the machine
// at all. There is nothing to delete afterwards and nothing to leak: we were never
// sent it.
package redact

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Text hides every account name in names, every SSH key, and every address.
//
// It takes the names rather than reading them, so the reading happens once per job
// instead of once per command, and so a test can say exactly who lives on the machine.
func Text(names []string, s string) string {
	if s == "" {
		return s
	}
	s = maskKeys(s)
	s = maskAddresses(s)
	return maskNames(names, s)
}

// keepLetters is how much of a name stays readable.
//
// Two is enough to tell two accounts apart in a report — `ed***` and `de****` are
// clearly different people — and not enough to name either of them.
const keepLetters = 2

// Name hides one account name, keeping its length.
//
// The length stays because a report is read by somebody who knows their own server:
// seeing that two different accounts appear, and that one is longer, is the difference
// between a readable report and a wall of stars. A name is not a secret in the way a
// key is; it is personal data, and covering it is enough.
func Name(name string) string {
	if len(name) <= keepLetters {
		return strings.Repeat("*", len(name))
	}
	return name[:keepLetters] + strings.Repeat("*", len(name)-keepLetters)
}

func maskNames(names []string, s string) string {
	for _, name := range names {
		// notPeople is applied here as well as in Accounts, because masking root
		// would make our own commands unreadable — every install grant says
		// `-o root -g root` — and root is not anybody in particular.
		if name == "" || notPeople[name] {
			continue
		}
		s = wordPattern(name).ReplaceAllLiteralString(s, Name(name))
	}
	return s
}

// wordPattern matches the name on its own, never inside a longer word.
//
// Without it `edyan` would be masked inside `edyanx` and inside `/var/edyan-backups`,
// and a report of half-masked words is one nobody reads. `\b` treats `-` and `/` as
// boundaries, which is what makes `/home/edyan/` match and `edyanx` not.
func wordPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
}

// sshKey matches an authorized_keys line: the type, the body, and an optional comment.
var sshKey = regexp.MustCompile(`\b(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/=]+)(\s+(\S+))?`)

// keyMask is a fixed width, unlike a name.
//
// A key's length says which algorithm and which size, and keeping it would leak
// something for nothing: nobody reading a report needs to tell two keys apart by
// their length. The type is kept, because `ssh-rsa` versus `ssh-ed25519` is exactly
// the kind of thing a person is being asked to judge.
const keyMask = "****"

// keepCommentLetters is how much of a key's comment stays. A comment is usually
// `somebody@somewhere`, so it is a name twice over, and three letters is enough to
// tell two keys apart in a list.
const keepCommentLetters = 3

func maskKeys(s string) string {
	return sshKey.ReplaceAllStringFunc(s, func(match string) string {
		parts := sshKey.FindStringSubmatch(match)
		masked := parts[1] + " " + keyMask
		if comment := parts[4]; comment != "" {
			masked += " " + maskComment(comment)
		}
		return masked
	})
}

func maskComment(comment string) string {
	if len(comment) <= keepCommentLetters {
		return keyMask
	}
	return comment[:keepCommentLetters] + keyMask
}

// alwaysReadable are the addresses that are nobody's.
//
// `0.0.0.0/0` and `::/0` mean "the whole internet", which is the single most important
// thing a firewall rule can say — masking it would hide the very fact somebody is
// being asked to judge. `127.0.0.1` and `::1` mean "this machine" and are the same on
// every machine that has ever existed.
var alwaysReadable = map[string]bool{
	"0.0.0.0": true, "255.255.255.255": true,
	"::": true, "::1": true, "127.0.0.1": true,
}

// ipv4 matches an address with an optional prefix length.
var ipv4 = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?\b`)

// word is a whole run of the characters an address can be made of, plus the letters and
// dashes it cannot.
//
// Matching the whole word is the point. A pattern that matched only the address-shaped
// part of a word found `::A` inside `APT::Architecture` — a valid IPv6 address, because
// A to F are hex letters — and mangled every apt setting whose name began with one.
// Found in the real output of `apt-config dump` on debian-13. net.ParseIP then decides,
// because a regexp that gets IPv6 right is a regexp nobody can read.
var word = regexp.MustCompile(`[0-9A-Za-z:._%/-]+`)

func maskAddresses(s string) string {
	s = ipv4.ReplaceAllStringFunc(s, func(match string) string {
		address, prefix := splitPrefix(match)
		if net.ParseIP(address) == nil || alwaysReadable[address] {
			return match
		}
		first, _, _ := strings.Cut(address, ".")
		return first + ".*.*.*" + prefix
	})

	return word.ReplaceAllStringFunc(s, func(match string) string {
		address, prefix := splitPrefix(match)
		address, zone := splitZone(address)
		parsed := net.ParseIP(address)
		if parsed == nil || parsed.To4() != nil || alwaysReadable[address] {
			return match
		}
		return firstGroup(address) + strings.Repeat(":*", groupsInIPv6-1) + zone + prefix
	})
}

// firstGroup is the part of an IPv6 address before the first colon.
//
// It is kept for the same reason the first number of an IPv4 address is: it says
// whether the address is on this network, on a private range, or somewhere on the
// internet, without saying whose it is. An address starting `::` has no first group.
func firstGroup(address string) string {
	group, _, _ := strings.Cut(address, ":")
	return group
}

// groupsInIPv6 is how many colon-separated groups an address has when it is written out
// in full. Keeping the count makes a masked address recognisable as one.
const groupsInIPv6 = 8

// splitZone separates a link-local address from its interface — fe80::1%eth0.
//
// The interface name is not personal data and it is the useful half: "which network
// card" is a question a sysadmin asks. net.ParseIP does not accept a zone, so it has to
// come off before the address can be recognised at all.
func splitZone(address string) (bare, zone string) {
	if i := strings.Index(address, "%"); i >= 0 {
		return address[:i], address[i:]
	}
	return address, ""
}

func splitPrefix(match string) (address, prefix string) {
	if i := strings.LastIndex(match, "/"); i >= 0 {
		return match[:i], match[i:]
	}
	return match, ""
}

// mustParseUID keeps the passwd parsing honest: a line whose uid is not a number is a
// line we do not understand, and guessing what it means is how a person's name gets
// sent.
func mustParseUID(field string) (int, error) {
	var uid int
	if _, err := fmt.Sscanf(field, "%d", &uid); err != nil {
		return 0, fmt.Errorf("uid %q is not a number", field)
	}
	return uid, nil
}
