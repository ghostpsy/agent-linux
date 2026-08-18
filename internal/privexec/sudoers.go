//go:build linux

package privexec

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Sudoers renders the privilege grant for user, from the same registry Run
// consults. One source, two consumers: the file on disk and the agent's
// behaviour cannot drift apart.
func Sudoers(user string) string {
	var b strings.Builder
	// Several commands share one binary, and sudo needs its env_keep stated
	// once. Repeating it would be noise in a file whose only job is to be read.
	envDone := map[string]bool{}

	for _, id := range sortedIDs() {
		declared := registry[id]

		// A command that needs no privilege gets none. The grant file's whole
		// value is that it is short enough for a sysadmin to read and judge.
		if declared.Unprivileged {
			continue
		}

		// The file is generated on the host it applies to, so grant only what
		// is actually installed. Privilege for a binary that is not there is
		// noise in a file whose whole value is that a human can read it.
		path, err := resolve(declared.Binary)
		if err != nil {
			continue
		}

		// The same rule one level further on: a command whose destination is not
		// here cannot apply here, and a grant that can never apply is noise in a
		// file whose whole value is that a human can read it.
		if declared.NeedsPath != "" {
			if _, err := os.Stat(declared.NeedsPath); err != nil {
				continue
			}
		}

		if declared.Why != "" {
			fmt.Fprintf(&b, "# %s\n", declared.Why)
		}
		// A wildcard is all sudo understands, so the reader is told in words
		// what the agent will put there. A grant a sysadmin cannot judge is not
		// the promise we made.
		for _, param := range declared.Params {
			if param.Why != "" {
				fmt.Fprintf(&b, "#   the * is %s\n", param.Why)
			}
		}
		if keys := envKeys(declared.Env); keys != "" && !envDone[path] {
			fmt.Fprintf(&b, "Defaults!%s env_keep += %q\n", path, keys)
			envDone[path] = true
		}
		grant := strings.TrimRight(path+" "+strings.Join(grantArgs(declared), " "), " ")
		fmt.Fprintf(&b, "%s ALL=(root) NOPASSWD: %s\n", user, grant)
	}

	return b.String()
}

// resolve returns the absolute path of a declared binary on this host, or an
// error if it is not installed.
func resolve(binary string) (string, error) {
	if strings.HasPrefix(binary, "/") {
		if _, err := os.Stat(binary); err != nil {
			return "", err
		}
		return binary, nil
	}
	return exec.LookPath(binary)
}

func sortedIDs() []ID {
	ids := make([]ID, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// envKeys turns declared KEY=VALUE pairs into the space-separated key list
// sudo's env_keep expects.
func envKeys(env []string) string {
	keys := make([]string, 0, len(env))
	for _, kv := range env {
		if key, _, ok := strings.Cut(kv, "="); ok {
			keys = append(keys, key)
		}
	}
	return strings.Join(keys, " ")
}
