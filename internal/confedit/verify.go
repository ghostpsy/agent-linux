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

	want := strings.ToLower(directiveLine(s, value))
	for _, line := range strings.Split(effective, "\n") {
		if strings.ToLower(strings.TrimSpace(line)) == want {
			return fmt.Sprintf("%s is running with %s.", serviceName(s), directiveLine(s, value)), nil
		}
	}

	// Say what it does think, when we can, so the person is not left guessing.
	current := "something else"
	for _, line := range strings.Split(effective, "\n") {
		if isLiveDirective(s, line) {
			current = directiveLine(s, directiveValue(s, line))
			break
		}
	}
	return "", fmt.Errorf(
		"%s did not take the change: it is running with %s, not %s",
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
