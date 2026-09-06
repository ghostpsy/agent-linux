//go:build linux

package privexec

import "testing"

// sshd -T has to be a declared command, or the SSH findings are always empty.
//
// This is the bug it was written for. internal/collect/identity/host_ssh.go ran
// exec.Command("sshd", "-T") directly, with no privilege at all. As the ghostpsy
// user, sshd cannot read a drop-in such as /etc/ssh/sshd_config.d/50-cloud-init.conf,
// which ships mode 0600 root — so the command failed on every machine and every
// SSH finding was silently absent: PermitRootLogin, PasswordAuthentication,
// the ciphers, MaxAuthTries, all of it.
//
// Declaring it also puts `sshd -T` in the grant file, so a security team reads a
// standard command instead of trusting our binary.
func TestSSHDumpConfigIsDeclared(t *testing.T) {
	cmd, ok := registry[SSHDumpConfig]
	if !ok {
		t.Fatal("sshd -T is not declared, so it runs unprivileged and reads nothing")
	}
	if cmd.Binary != "sshd" {
		t.Errorf("binary: got %q, want sshd", cmd.Binary)
	}
	// -T dumps the effective configuration. -t only checks it and prints nothing
	// worth parsing, and the two are one shift key apart.
	if len(cmd.Args) != 1 || cmd.Args[0] != "-T" {
		t.Errorf("args: got %v, want [-T]", cmd.Args)
	}
	if cmd.Binary == registry[SSHTestConfig].Binary && cmd.Args[0] == registry[SSHTestConfig].Args[0] {
		t.Error("this is the config test, not the config dump")
	}
}
