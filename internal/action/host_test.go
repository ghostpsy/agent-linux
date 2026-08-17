//go:build linux

package action

import (
	"sort"
	"testing"
)

// A real /proc/net/tcp, in the shape the kernel writes it.
//
// Three rows, and telling them apart is the whole job:
//
//	sshd listening on 22                       — 0016, state 0A
//	somebody connected to us on 22             — local 0016, state 01
//	the agent talking to our API on port 8000  — local A23A (41530), state 01
//
// The third one is why this test exists. See below.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 1C40A8C0:0016 1E40A8C0:F1B2 01 00000000:00000000 02:000AF1B2 00000000     0        0 23456 1 0000000000000000 20 4 30 10 -1
   2: 1C40A8C0:A23A 0140A8C0:1F90 01 00000000:00000000 02:000AF1B2 00000000   999        0 34567 1 0000000000000000 20 4 30 10 -1
`

// The failure this catches, found on a real machine on the second end-to-end run.
//
// The check that a change has not cut off the operator was looking at the local
// port of every established connection. For a connection *to* this machine that
// is the port somebody reached it on — port 22, which is what we want. But for a
// connection *from* this machine it is an ephemeral source port, and the agent
// always has one of those open: it is how it talks to us.
//
// So the check asked "is anything listening on port 41530?", found nothing, and
// concluded the machine had become unreachable. It then correctly rolled back a
// change that had worked perfectly. Every safety mechanism did its job; the
// question was wrong.
func TestOnlyPortsSomebodyIsReachingThisMachineOnCount(t *testing.T) {
	ports := establishedLocalPorts(procNetTCP)
	sort.Ints(ports)

	if len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("expected only port 22 — the one somebody is connected on — got %v.\n"+
			"41530 is the agent's own outgoing connection to the service, not a way in.", ports)
	}
}

// A machine with no inbound connection at all has no session to protect. That has
// to be an honest "nothing to check", not a port list with an outbound socket in it.
func TestAMachineNobodyIsConnectedToHasNoPortsToProtect(t *testing.T) {
	onlyOutbound := `  sl  local_address rem_address   st ...
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 1C40A8C0:A23A 0140A8C0:1F90 01 00000000:00000000 02:000AF1B2 00000000   999        0 2 1 0 20 4 30 10 -1
`

	if ports := establishedLocalPorts(onlyOutbound); len(ports) != 0 {
		t.Fatalf("expected no inbound ports, got %v", ports)
	}
}

// A connection on a port nothing listens on cannot be inbound, whatever its
// state says. Requiring the port to be listening is what makes the answer exact,
// rather than a guess about which numbers look ephemeral.
func TestAnEstablishedConnectionOnAPortNothingListensOnIsNotInbound(t *testing.T) {
	noListener := `  sl  local_address rem_address   st ...
   0: 1C40A8C0:0016 1E40A8C0:F1B2 01 00000000:00000000 02:000AF1B2 00000000     0        0 1 1 0 20 4 30 10 -1
`

	if ports := establishedLocalPorts(noListener); len(ports) != 0 {
		t.Fatalf("expected nothing, got %v", ports)
	}
}

func TestTheMachineTalkingToItselfIsNotAWayIn(t *testing.T) {
	loopback := `  sl  local_address rem_address   st ...
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:0016 0100007F:F1B2 01 00000000:00000000 02:000AF1B2 00000000     0        0 2 1 0 20 4 30 10 -1
`

	if ports := establishedLocalPorts(loopback); len(ports) != 0 {
		t.Fatalf("a connection from this machine to itself is not a way in, got %v", ports)
	}
}
