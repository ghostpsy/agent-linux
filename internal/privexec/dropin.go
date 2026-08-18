//go:build linux

package privexec

import (
	"fmt"
	"path/filepath"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// Writing a setting is an `install` of a file that shipped with the agent.
//
// This is what lets the grant be literal. Both paths are named in full, the source
// is root-owned and read-only so its content was fixed before the command ran, and
// the command itself is one a sysadmin recognises. It replaces four grants of the
// form `ghostpsy write-config --mode=apply --key=* --value=*`, where the list of
// what could be written lived in our binary and the file on the server said only
// "any setting, any value".
//
// A wildcard was never an option: measured on debian-13, a `*` in a sudoers
// argument matches `/` too, so `cat /tmp/gpd/*.conf` read a 0600 file two
// directories up. A regex needs sudo 1.9.10, and CentOS 7 ships 1.8.23.
//
// One command is declared per setting-and-value pair, and one per setting for the
// undo. That is 9 and 6 today. The list comes from confedit, so a new setting cannot
// be reachable without also appearing in the grant file.

// InstallDropIn names the command that makes one change.
func InstallDropIn(c confedit.Change) ID {
	return ID(fmt.Sprintf("config.install.%s=%s", c.Setting.Key, c.Value))
}

// RemoveDropIn names the command that undoes every value of one setting.
func RemoveDropIn(s confedit.Setting) ID {
	return ID("config.remove." + s.Key)
}

func init() {
	for _, change := range confedit.Changes() {
		drop := change.DropIn()

		declare(InstallDropIn(change), Command{
			Binary: "install",
			// -o root -g root is stated rather than assumed. The command runs as
			// root, so it would default to that anyway — but the grant is read by a
			// person deciding whether to trust it, and a line that says who will own
			// the file answers a question they would otherwise have to ask.
			Args:      []string{"-m", drop.Mode, "-o", "root", "-g", "root", drop.Source, drop.Dest},
			NeedsPath: filepath.Dir(drop.Dest),
			Why: fmt.Sprintf("set %s to %s, by installing a file that shipped with this agent. "+
				"Its content is fixed and root-owned, so this command can write nothing else",
				change.Setting.Directive, change.Value),
		})
	}

	for _, setting := range confedit.All() {
		if len(setting.Allow) == 0 {
			continue
		}
		declare(RemoveDropIn(setting), Command{
			Binary:    "rm",
			Args:      []string{Change(setting).DropIn().Dest},
			NeedsPath: filepath.Dir(Change(setting).DropIn().Dest),
			Why: fmt.Sprintf("undo a change to %s by removing the file that made it, "+
				"which puts this server back to what it decided for itself", setting.Directive),
		})
	}
}

// Change is the setting at its first allowed value.
//
// Every value of a setting goes to the same destination, so any of them gives the
// path the undo needs. Taking the first is not a choice about which value to use —
// there is only one path to name.
func Change(s confedit.Setting) confedit.Change {
	return confedit.Change{Setting: s, Value: s.Allow[0]}
}
