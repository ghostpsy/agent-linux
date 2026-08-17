//go:build linux

package action

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// HostDeps is the runner wired to this machine.
//
// Everything the runner touches outside itself lives behind these functions, so
// the rules about when we change a customer's server are all testable without
// changing one. This is the only place those functions are real.
func HostDeps() Deps {
	return Deps{
		Exec:         privexec.RunWith,
		Installed:    installed,
		FreeBytes:    FreeBytes,
		SwitchedOff:  SwitchedOff,
		InboundPorts: inboundPorts,
		Listening:    listening,
		Protected:    Protected,
		Sleep:        sleep,
	}
}

func installed(binary string) bool {
	if strings.HasPrefix(binary, "/") {
		_, err := os.Stat(binary)
		return err == nil
	}
	_, err := exec.LookPath(binary)
	return err == nil
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

// tcpStateEstablished is the value the kernel writes for a live connection.
const tcpStateEstablished = "01"

// establishedLocalPorts reads the local port of every established connection
// whose other end is not this machine.
func establishedLocalPorts(table string) []int {
	var ports []int

	for i, line := range strings.Split(table, "\n") {
		if i == 0 {
			continue // the header
		}
		fields := strings.Fields(line)
		// local_address is field 1, rem_address 2, st 3.
		if len(fields) < 4 || fields[3] != tcpStateEstablished {
			continue
		}
		if isLoopbackHex(fields[2]) {
			continue
		}
		port, err := strconv.ParseInt(hexPort(fields[1]), 16, 32)
		if err != nil {
			continue
		}
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
