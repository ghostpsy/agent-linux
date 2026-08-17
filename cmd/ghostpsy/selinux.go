//go:build linux

package main

import "os/exec"

// On a server with SELinux, having the right owner and the right permissions is
// not enough. A file also carries a security label, and the label decides what
// may run it.
//
// A label is inherited from the directory a file is *created* in, and a rename
// keeps it. So the ordinary way an admin puts a binary on a server —
//
//	scp ghostpsy server:/tmp/ && sudo mv /tmp/ghostpsy /usr/local/bin/
//
// leaves it labelled as a temporary file, and systemd then refuses to execute it
// at all: 203/EXEC, over and over. Found on a real Rocky 9 machine, where the
// installer reported success and the service crash-looped.
//
// restorecon sets the label the system's own policy says that path should have.
// It is the same thing the distribution's package manager does, and running it is
// how the agent stops depending on how its binary arrived.

// relabelForSELinux puts the system's own labels back on the paths the agent
// needs, on a host that uses SELinux.
//
// It does nothing at all on a host without SELinux, which is most of them. A
// missing restorecon is not an error: it means this machine has no policy to
// enforce, so there is nothing to put right.
func relabelForSELinux(paths []string, look lookPathFn, run runCmdFn) error {
	restorecon, err := look("restorecon")
	if err != nil {
		return nil
	}

	for _, path := range paths {
		// Failures are deliberately not fatal. restorecon exits non-zero for a
		// path its policy says nothing about, which is normal and harmless — and
		// refusing to install over it would break machines that were fine.
		_ = run(restorecon, "-F", path)
	}
	return nil
}

type lookPathFn func(string) (string, error)
type runCmdFn func(name string, args ...string) error

func lookPath(name string) (string, error) { return exec.LookPath(name) }

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run() //nolint:gosec // a resolved path and fixed arguments
}
