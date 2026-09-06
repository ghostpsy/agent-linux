//go:build linux

package identity

import (
	"strconv"
	"strings"
	"time"
)

// passwdStatus is what `passwd -S -a` tells us, counted.
type passwdStatus struct {
	total      int
	locked     int
	noPassword int
	expired    int
}

// passwdStatusFields is how many fields a well formed status line has:
// account, status, last change, min days, max days, warn days, inactive days.
const passwdStatusFields = 7

// parsePasswdStatus counts accounts from `passwd -S -a`.
//
// This replaced reading /etc/shadow through our own binary. The old way was
// safe but unreadable: the sudo rule said `ghostpsy read-shadow`, and a security
// team could only find out what that did by reading our source. `passwd -S -a`
// is a command they already know, and its output carries no password material —
// only a status letter per account. Same numbers, nothing to take on trust.
//
// A line that is not the expected shape is skipped rather than guessed at. One
// odd account must not cost us the count of the other twenty.
func parsePasswdStatus(raw []byte) passwdStatus {
	var out passwdStatus
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != passwdStatusFields {
			continue
		}
		out.total++
		switch fields[1] {
		case "L":
			out.locked++
		case "NP":
			out.noPassword++
		}
		if passwordIsExpired(fields[2], fields[4]) {
			out.expired++
		}
	}
	return out
}

// passwordIsExpired reports whether a password is older than the maximum age set
// for it, which means the account must change it at the next login.
//
// A maximum of 99999 days is shadow's way of saying "never expires", and it is
// the default on every distribution — treating it as an expiry would report
// almost every account on almost every server.
func passwordIsExpired(lastChange, maxDays string) bool {
	maximum, err := strconv.Atoi(maxDays)
	if err != nil || maximum <= 0 || maximum >= neverExpiresDays {
		return false
	}
	changed, err := time.Parse(time.DateOnly, lastChange)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(changed.AddDate(0, 0, maximum))
}

// neverExpiresDays is the maximum age that means "never". shadow uses 99999.
const neverExpiresDays = 99999

// neverLoggedInMarker is what lastlog prints for an account that has never been
// used. It is the same string on every distribution that ships shadow-utils.
const neverLoggedInMarker = "**Never logged in**"

// countNeverLoggedIn counts the accounts lastlog says have never been used.
func countNeverLoggedIn(raw []byte) int {
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, neverLoggedInMarker) {
			count++
		}
	}
	return count
}
