//go:build linux

package action

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/confedit"
	"github.com/ghostpsy/agent-linux/internal/privexec"
	"github.com/ghostpsy/agent-linux/internal/redact"
)

// HostDeps is the runner wired to this machine.
//
// Everything the runner touches outside itself lives behind these functions, so
// the rules about when we change a customer's server are all testable without
// changing one. This is the only place those functions are real.
func HostDeps() Deps {
	return Deps{
		Exec:         privexec.RunWith,
		Installed:    privexec.Installed,
		Applies:      privexec.Applies,
		FreeBytes:    FreeBytes,
		SwitchedOff:  SwitchedOff,
		InboundPorts: inboundPorts,
		Listening:    listening,
		Protected:    Protected,
		SSHAccess:    sshAccess,
		Accounts:     redact.Accounts,
		Sleep:        sleep,
	}
}

// sshAccess counts the ways into this machine.
//
// Two steps, and only the second one is privileged. /etc/passwd is world-readable,
// so the accounts, their homes and their shells are read here as an ordinary
// user. The single thing that needs root is looking inside a home directory for a
// key file, and that is one `find` a reviewer can read in the grant.
//
// It used to be `ghostpsy read-ssh-access`, which did all of it as root.
func sshAccess(ctx context.Context) (confedit.Access, error) {
	passwdContent, err := confedit.ReadPasswd()
	if err != nil {
		return confedit.Access{}, fmt.Errorf("could not read the list of accounts: %w", err)
	}
	res, err := privexec.RunWith(ctx, privexec.AuthorizedKeysFiles, nil)
	if err != nil {
		return confedit.Access{}, fmt.Errorf("could not ask this machine who can log in: %w", err)
	}
	return confedit.AccessFromKeyFiles(passwdContent, strings.Split(string(res.Stdout), "\n")), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// listening reports whether anything is accepting connections on a local port.
//
// It dials rather than reads a table: a socket that is bound but whose service
// has wedged still shows up in /proc, and "the port is in a list" is not the
// thing the operator cares about. Being answered is.
func listening(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// inboundPorts lists the local ports of TCP connections somebody has open to
// this machine right now.
//
// This is how a firewall change is stopped before it cuts off the person making
// it. Only established connections count, and only ones from somewhere else:
// a connection from the machine to itself is not a way in.
func inboundPorts() ([]int, error) {
	ports := map[int]bool{}

	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := os.ReadFile(table) //nolint:gosec // a fixed kernel path
		if err != nil {
			// tcp6 is absent on a host without IPv6. That is normal, not a
			// failure, so the other table still counts.
			continue
		}
		for _, port := range establishedLocalPorts(string(content)) {
			ports[port] = true
		}
	}

	if len(ports) == 0 {
		// Distinguishing "nobody is connected" from "we could not tell" matters:
		// the first is a pass, the second must never be. An unreadable /proc is
		// the second, and it is why the tables above are read at all.
		if _, err := os.Stat("/proc/net/tcp"); err != nil {
			return nil, err
		}
	}

	out := make([]int, 0, len(ports))
	for port := range ports {
		out = append(out, port)
	}
	return out, nil
}

// The two states the kernel writes that this cares about.
const (
	tcpStateEstablished = "01"
	tcpStateListen      = "0A"
)

// establishedLocalPorts reads the ports somebody is reaching this machine on.
//
// A connection is inbound only if its local port is also a port this machine
// listens on. That is what tells the two directions apart, and getting it wrong
// is not cosmetic: an outgoing connection's local port is an ephemeral source
// port, and the agent always has one open — it is how it talks to us. Counting
// that as a way in made the reachability check ask whether anything was listening
// on port 41530, and roll back a change that had worked perfectly.
//
// Requiring the port to be listening is exact. Guessing which numbers look
// ephemeral would be a guess, on the one check that must not be wrong.
func establishedLocalPorts(table string) []int {
	listening := map[string]bool{}
	rows := strings.Split(table, "\n")

	for _, line := range rows {
		if fields := strings.Fields(line); len(fields) >= 4 && fields[3] == tcpStateListen {
			listening[hexPort(fields[1])] = true
		}
	}

	var ports []int
	seen := map[int]bool{}
	for _, line := range rows {
		fields := strings.Fields(line)
		// local_address is field 1, rem_address 2, st 3.
		if len(fields) < 4 || fields[3] != tcpStateEstablished {
			continue
		}
		// This machine talking to itself is not a way in.
		if isLoopbackHex(fields[2]) {
			continue
		}
		local := hexPort(fields[1])
		if !listening[local] {
			continue
		}
		port, err := strconv.ParseInt(local, 16, 32)
		if err != nil || seen[int(port)] {
			continue
		}
		seen[int(port)] = true
		ports = append(ports, int(port))
	}
	return ports
}

func hexPort(address string) string {
	_, port, found := strings.Cut(address, ":")
	if !found {
		return ""
	}
	return port
}

// isLoopbackHex reports whether a /proc address is this machine talking to
// itself. The kernel writes the address little-endian, so 127.0.0.1 is
// 0100007F, and IPv6 loopback ends in ...00000001.
func isLoopbackHex(address string) bool {
	host, _, found := strings.Cut(address, ":")
	if !found {
		return false
	}
	switch strings.ToUpper(host) {
	case "0100007F", "00000000000000000000000001000000":
		return true
	}
	return false
}
