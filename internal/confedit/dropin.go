//go:build linux

package confedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A drop-in is a whole file of our own, not an edit to somebody else's.
//
// That is what makes the sudo grant literal. `install <source> <destination>` names
// both paths exactly, and the source ships with the agent as root:root 0444 — so
// the content is fixed before the command runs and there is nothing left for the
// grant to leave open. An edit to a shared file cannot be granted that way: the text
// to write depends on what the file already holds, which nobody knows in advance.
//
// One file per setting, not one file for all of them. A shared file would hold
// whichever settings happen to be applied, and that is a combination — 40 possible
// contents for the four SSH settings, so 39 shipped files instead of 7. It would
// also make undoing one setting a rewrite of the others.

const (
	// dropInSourceDir is where the shipped files live. Installed by root as
	// root:root 0444: the ghostpsy user must not be able to change the content it
	// will ask root to install, or the grant bounds the destination and nothing else.
	dropInSourceDir = "/usr/local/lib/ghostpsy/dropin"

	// sshDropInDir and sshDropInPrefix — sshd keeps the FIRST value it sees, and the
	// distributions ship 50-cloud-init.conf and 50-redhat.conf. Measured on
	// debian-13 and rocky-9: a 10- file beat both a later live line in the main
	// config and a 99- drop-in. So ours sorts below 50.
	sshDropInDir    = "/etc/ssh/sshd_config.d"
	sshDropInPrefix = "10-ghostpsy-"

	// aptDropInDir and aptDropInPrefix — apt is the opposite: the LAST file wins.
	// Measured: 90- beat 10-. So ours sorts high.
	aptDropInDir    = "/etc/apt/apt.conf.d"
	aptDropInPrefix = "99-ghostpsy-"

	// dropInSuffix — measured: apt ignores a file in apt.conf.d unless it has no
	// extension or ends in .conf. A file named 99-ghostpsy.disabled was read by
	// nobody, which would make a fix report success and change nothing.
	dropInSuffix = ".conf"

	// sshDropInMode matches what cloud-init and Red Hat use for their own drop-ins
	// on the same directory. aptDropInMode matches apt's own files, which are read
	// by tools running as other users.
	sshDropInMode = "0600"
	aptDropInMode = "0644"
)

// DropIn is the file that carries one setting at one value.
type DropIn struct {
	// Source ships with the agent. Fixed content, owned by root.
	Source string

	// Dest is where it is installed to. One per setting, so an undo is `rm` of one
	// exact path.
	Dest string

	// Mode is passed to `install -m`, so it is the literal text of a command
	// argument and of the grant line.
	Mode string

	Content string
}

// DropIn is the file that makes this change, and the file that undoes it.
func (c Change) DropIn() DropIn {
	dir, prefix, mode := aptDropInDir, aptDropInPrefix, aptDropInMode
	if c.Setting.Style == StyleSSH {
		dir, prefix, mode = sshDropInDir, sshDropInPrefix, sshDropInMode
	}

	return DropIn{
		Source: fmt.Sprintf("%s/%s=%s%s", dropInSourceDir, c.Setting.Key, c.Value, dropInSuffix),
		Dest:   fmt.Sprintf("%s/%s%s%s", dir, prefix, settingSlug(c.Setting), dropInSuffix),
		Mode:   mode,
		// The note says a tool wrote this, and which one. The person who finds the
		// file in six months has no other way to know.
		Content: "# set by ghostpsy\n" + directiveLine(c.Setting, c.Value) + "\n",
	}
}

// settingSlug turns a setting key into the part of a file name a person can read.
//
// `ssh.max_auth_tries` becomes `max-auth-tries`. The prefix goes because the
// directory already says which service it is.
func settingSlug(s Setting) string {
	_, name, found := strings.Cut(s.Key, ".")
	if !found {
		name = s.Key
	}
	return strings.ReplaceAll(name, "_", "-")
}

// shippedMode is what a shipped drop-in gets: readable by anyone, writable by
// nobody, not even root without asking twice.
//
// This is the point of the whole design. If the ghostpsy user could write these
// files it would put anything it liked in one and then ask root to install it —
// and the grant, which pins only the two paths, would allow it. `PermitRootLogin
// yes` in a file we asked root to copy into sshd_config.d is root on the server.
const shippedMode os.FileMode = 0o444

// Applicable is the changes this server can actually take.
//
// A drop-in needs somewhere to go. rocky-9 has no /etc/apt/apt.conf.d, so shipping
// the two apt files there would leave them sitting unusable forever and make
// `ghostpsy dropins` offer a fix that cannot happen. The sudo grant follows the same
// rule one level down, through Command.NeedsPath.
//
// root is "" in production and a temporary directory in tests.
func Applicable(root string) []Change {
	var out []Change
	for _, c := range Changes() {
		dir := filepath.Join(root, filepath.Dir(c.DropIn().Dest))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

// WriteDropIns writes every shipped file this server can use, and returns the paths
// it wrote.
//
// root is "" in production and a temporary directory in tests. It is a parameter
// rather than an environment variable because these paths also appear in the sudo
// grant, where they must always be the real ones — so the redirection has to be
// visible at the call site, not hidden inside a path helper.
//
// The installer calls this as root. It is safe to call again on an upgrade: each
// file is written whole to a temporary name and renamed over the old one, which
// works even though the old one is read-only.
func WriteDropIns(root string) ([]string, error) {
	dir := filepath.Join(root, dropInSourceDir)
	if err := os.MkdirAll(dir, dropInDirMode); err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dir, err)
	}

	var written []string
	for _, c := range Applicable(root) {
		path := filepath.Join(root, c.DropIn().Source)
		if err := writeAtomic(path, c.DropIn().Content, shippedMode); err != nil {
			return nil, fmt.Errorf("could not write %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// dropInDirMode lets anyone look at the directory and nobody but root add to it.
const dropInDirMode os.FileMode = 0o755

// DropInSourceDir is where the shipped files live, for a message that tells
// somebody where to look.
func DropInSourceDir() string { return dropInSourceDir }

// SSHConfigPath is the main SSH configuration file, for a command that reads it.
func SSHConfigPath() string { return sshdConfigPath }

// DropInDirFor is where this setting's drop-in goes, for a message that names it.
//
// Derived from the destination rather than decided again, so a message can never name
// a directory the file does not go into. Dest does not depend on the value: every value
// of a setting writes the same path, which is what makes the undo one `rm`.
func DropInDirFor(s Setting) string {
	return filepath.Dir(Change{Setting: s}.DropIn().Dest)
}
