//go:build linux

package action

// PossibleOn lists the actions this machine could actually carry out.
//
// It exists because the plan is built somewhere else. The cloud reads the scan
// report, which says what is wrong with a server but not what that server can do
// about it — so harden_ssh_config was offered on an Ubuntu 14.04 host with no
// systemd to reload sshd and no sshd_config.d to drop a file into. The person
// ticked it, approved it, and was told only then that it could never work.
//
// The alternative was teaching the cloud the same rules in Python. That is the
// same knowledge in two languages, and the two would drift — which is how the
// morning's apt failure and this one are the same bug twice. So the agent, which
// already decides this every time it runs, says it once with the scan.
//
// It is not a security boundary and does not try to be. The agent still refuses
// anything it cannot do, whatever the cloud sends; this only stops the screen
// offering work that was never going to happen.
func PossibleOn(deps Deps) []string {
	possible := make([]string, 0, len(All()))
	for _, candidate := range All() {
		if _, found := pickVariant(deps, candidate); found {
			possible = append(possible, candidate.Type)
		}
	}
	return possible
}
