//go:build linux

package network

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestProbeInternetListeners_SkipsWhenNoPublicIP(t *testing.T) {
	listeners := []payload.Listener{
		{Port: 80, Bind: "0.0.0.0:80", Process: "nginx", ExposureRisk: "internet_exposed"},
	}
	result := ProbeInternetListeners(context.Background(), listeners, nil)
	if result[0].WanProbeOpen != nil {
		t.Fatal("expected WanProbeOpen to be nil when no public IP")
	}

	f := false
	hn := &payload.HostNetwork{HasPublicIPv4: &f}
	result = ProbeInternetListeners(context.Background(), listeners, hn)
	if result[0].WanProbeOpen != nil {
		t.Fatal("expected WanProbeOpen to be nil when has_public_ipv4 is false")
	}
}

func TestProbePort_OpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot create test listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	loopback := net.ParseIP("127.0.0.1")
	open := probePort(context.Background(), []net.IP{loopback}, port)
	if !open {
		t.Errorf("expected port %d to be reported as open", port)
	}
}

func TestProbePort_ClosedPort(t *testing.T) {
	// Use a port that is very unlikely to be listening.
	closed := probePort(context.Background(), []net.IP{net.ParseIP("127.0.0.1")}, 1)
	if closed {
		t.Error("expected port 1 to be reported as closed")
	}
}

func TestFormatIPForDial(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "[::1]"},
		{"2001:db8::1", "[2001:db8::1]"},
	}
	for _, tc := range cases {
		got := formatIPForDial(net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("formatIPForDial(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestProbeInternetListeners_OnlyProbesInternetExposed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot create test listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Override IP collector so the probe targets the loopback listener.
	original := collectPublicIPs
	collectPublicIPs = func() []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
	defer func() { collectPublicIPs = original }()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	tr := true
	hn := &payload.HostNetwork{HasPublicIPv4: &tr}

	listeners := []payload.Listener{
		{Port: port, Bind: "0.0.0.0:" + portStr, Process: "test", ExposureRisk: "internet_exposed"},
		{Port: port, Bind: "127.0.0.1:" + portStr, Process: "test", ExposureRisk: "internal_only"},
	}

	result := ProbeInternetListeners(context.Background(), listeners, hn)

	if result[0].WanProbeOpen == nil {
		t.Fatal("expected internet_exposed listener to have WanProbeOpen set")
	}
	if result[1].WanProbeOpen != nil {
		t.Fatal("expected internal_only listener to have WanProbeOpen nil")
	}
}
