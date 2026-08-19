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

// The preview is three real commands: what the server has, what we would write, and
// what the service believes right now. No diff computed by us, nothing to take on
// trust — the second command prints the exact bytes the third one would change.

// ReadSSHConfig reads the main SSH configuration.
//
// Privileged, measured rather than assumed: as a normal user on rocky-9 this fails,
// because it ships sshd_config as 0600. debian-13 ships it 0644 but its
// 50-cloud-init.conf drop-in as 0600, so a complete read needs root there too.
const ReadSSHConfig ID = "config.read.sshd_config"

// SSHEffectiveConfig asks sshd what it actually believes.
//
// This is what decides whether a fix worked. Reading the file back would prove
// nothing: sshd_config pulls in other files with Include, the first value of a keyword
// wins, and a distribution can ship a drop-in nobody remembers.
const SSHEffectiveConfig ID = "config.effective.sshd"

// ShowDropIn names the command that prints what would be written.
func ShowDropIn(c confedit.Change) ID {
	return ID(fmt.Sprintf("config.show.%s=%s", c.Setting.Key, c.Value))
}

func init() {
	declare(ReadSSHConfig, Command{
		Binary: "cat",
		Args:   []string{confedit.SSHConfigPath()},
		Why: "read the SSH configuration, to find the Include line and any line that already " +
			"sets what is about to change. One named file, never a pattern",
		Env:       localeC,
		NeedsPath: confedit.SSHConfigPath(),
	})

	declare(SSHEffectiveConfig, Command{
		Binary: "sshd",
		Args:   []string{"-T"},
		Why: "ask the SSH server what settings it is actually running with, which is what " +
			"decides whether a change took effect",
		Env: localeC,
	})

	// Showing what would be written needs no privilege: the shipped files are 0444.
	// Granting root to read a world-readable file would be nine lines that buy nothing.
	for _, change := range confedit.Changes() {
		declare(ShowDropIn(change), Command{
			Binary:       "cat",
			Args:         []string{change.DropIn().Source},
			Why:          fmt.Sprintf("show the exact file that would set %s", change.Setting.Directive),
			Unprivileged: true,
		})
	}
}

// APTEffectiveConfig asks apt what configuration it is really using.
const APTEffectiveConfig ID = "config.effective.apt"

func init() {
	declare(APTEffectiveConfig, Command{
		Binary: "apt-config",
		Args:   []string{"dump"},
		Why: "ask apt what settings it is actually using, which is what decides whether a " +
			"change took effect",
		Env: localeC,
	})
}
