//go:build linux

package network

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// TestTelnetInInetdIsFound is the bug this reading exists for.
//
// On a real Ubuntu 14.04 host with telnet and rsh switched on in inetd.conf, the
// scan reported telnet_suspected false and rsh_suspected false. It had already
// opened the file and counted two live lines; nothing read what they said. The
// only question asked was systemd's, and that machine has no systemd — which is
// exactly the kind of machine still running telnet.
func TestTelnetInInetdIsFound(t *testing.T) {
	conf := "" +
		"#telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd\n" +
		"telnet\tstream\ttcp\tnowait\ttelnetd\t/usr/sbin/tcpd\t/usr/sbin/in.telnetd\n" +
		"shell\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t/usr/sbin/in.rshd\n"

	out := &payload.LegacyInsecureServices{}
	markLegacyServicesFromInetdText(out, conf)

	if !out.TelnetSuspected {
		t.Error("telnet is switched on in inetd.conf and was not reported")
	}
	if !out.RshSuspected {
		t.Error("rsh is switched on in inetd.conf and was not reported")
	}
	if out.RloginSuspected || out.RexecSuspected {
		t.Error("reported a service that is not in the file")
	}
}

// A line behind a # is how these services are usually turned off.
func TestACommentedServiceIsNotReported(t *testing.T) {
	conf := "" +
		"# telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd\n" +
		"#login  stream tcp nowait root    /usr/sbin/tcpd /usr/sbin/in.rlogind\n" +
		"\n"
	out := &payload.LegacyInsecureServices{}
	markLegacyServicesFromInetdText(out, conf)
	if out.TelnetSuspected || out.RloginSuspected {
		t.Fatalf("a commented line was reported as live: %+v", out)
	}
}

// rsh is "shell" and rlogin is "login" in /etc/services, and a machine may also
// name the service itself and be recognised by the program it runs.
func TestTheOldNamesAreUnderstood(t *testing.T) {
	out := &payload.LegacyInsecureServices{}
	markLegacyServicesFromInetdText(out, "login stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.rlogind\n")
	if !out.RloginSuspected {
		t.Error(`"login" is rlogin and was not reported`)
	}

	out2 := &payload.LegacyInsecureServices{}
	markLegacyServicesFromInetdText(out2, "myftp stream tcp nowait root /usr/sbin/vsftpd vsftpd\n")
	if !out2.VsftpdSuspected {
		t.Error("a service under a name of its own was not recognised by the program it runs")
	}
}
