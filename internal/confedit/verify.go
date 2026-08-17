//go:build linux

package confedit

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Verify checks the setting the *running service* actually has, not the file.
//
// Reading the file back would prove nothing. sshd_config can pull in other files
// with Include, a later line can override an earlier one, and a distribution can
// ship a drop-in nobody remembers. So the service is asked what it believes, and
// that answer is what decides whether the fix worked.
func Verify(s Setting, value string) (string, error) {
	effective, err := effectiveSettings(s)
	if err != nil {
		return "", err
	}
	if matchesEffective(s, value, effective) {
		return fmt.Sprintf("%s is running with %s.", serviceName(s), directiveLine(s, value)), nil
	}
	return "", fmt.Errorf("%s", explainMismatch(s, value, effective))
}

// sameMeaning lists values a service may report back under a different name.
//
// OpenSSH takes `prohibit-password` and prints `without-password`: the second is
// the older name for the same thing, and which one `sshd -T` shows depends on the
// build. Comparing the text alone therefore reported a correct server as wrong,
// and rolled back a change that had worked — found on a real machine, on the
// first end-to-end run.
//
// This is a synonym table, not a leniency table. It maps one value to other
// spellings of that *same* value, and never to a weaker one: `no` is stricter
// than `without-password`, so those two are not in here together.
var sameMeaning = map[string][]string{
	"prohibit-password": {"without-password"},
	"without-password":  {"prohibit-password"},
}

// matchesEffective reports whether the running service has this setting.
func matchesEffective(s Setting, value, effective string) bool {
	wanted := append([]string{value}, sameMeaning[value]...)

	for _, line := range strings.Split(effective, "\n") {
		if !isLiveDirective(s, line) {
			continue
		}
		current := directiveValue(s, line)
		for _, candidate := range wanted {
			if strings.EqualFold(current, candidate) {
				return true
			}
		}
	}
	return false
}

// explainMismatch says what the service is actually running.
//
// Without it a failed check is only "it did not work", which tells the person
// nothing they can act on.
func explainMismatch(s Setting, value, effective string) string {
	current := "something else"
	for _, line := range strings.Split(effective, "\n") {
		if isLiveDirective(s, line) {
			current = directiveLine(s, directiveValue(s, line))
			break
		}
	}
	return fmt.Sprintf("%s did not take the change: it is running with %s, not %s",
		serviceName(s), current, directiveLine(s, value))
}

// effectiveConfigTimeout bounds the question. Asking a service what it thinks
// must never be the reason a fix hangs.
const effectiveConfigTimeout = 30 * time.Second

// effectiveSettings asks the service what it is really using.
func effectiveSettings(s Setting) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), effectiveConfigTimeout)
	defer cancel()

	var cmd *exec.Cmd
	switch s.Style {
	case StyleSSH:
		// sshd -T prints the whole effective configuration, includes and all.
		cmd = exec.CommandContext(ctx, "sshd", "-T")
	case StyleAPTConf:
		cmd = exec.CommandContext(ctx, "apt-config", "dump")
	default:
		return "", fmt.Errorf("ghostpsy cannot check a %s setting", s.Style)
	}
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("could not ask %s what settings it is using: %w: %s",
			serviceName(s), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// serviceName is what to call the thing being checked, in words.
func serviceName(s Setting) string {
	switch s.Style {
	case StyleSSH:
		return "the SSH server"
	case StyleAPTConf:
		return "apt"
	}
	return s.File
}
