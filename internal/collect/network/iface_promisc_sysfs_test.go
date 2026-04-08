//go:build linux

package network

import "testing"

func TestPromiscFromSysfsFlagsContent(t *testing.T) {
	if !promiscFromSysfsFlagsContent([]byte("0x100\n")) {
		t.Fatal("expected promisc when IFF_PROMISC set alone")
	}
	if promiscFromSysfsFlagsContent([]byte("0x0\n")) {
		t.Fatal("expected not promisc")
	}
	if !promiscFromSysfsFlagsContent([]byte("0x301\n")) {
		t.Fatal("expected promisc when IFF_PROMISC combined with other bits")
	}
	if promiscFromSysfsFlagsContent([]byte("")) {
		t.Fatal("empty should be false")
	}
	if promiscFromSysfsFlagsContent([]byte("not-hex")) {
		t.Fatal("invalid hex should be false")
	}
}

func TestIsSafeSysfsIfaceName(t *testing.T) {
	if !isSafeSysfsIfaceName("eth0") {
		t.Fatal("eth0 should be safe")
	}
	if isSafeSysfsIfaceName("") || isSafeSysfsIfaceName("a/b") || isSafeSysfsIfaceName("..") {
		t.Fatal("expected unsafe")
	}
}

func TestPromiscFromSysfsForIface_invalidName(t *testing.T) {
	_, ok := promiscFromSysfsForIface("../lo")
	if ok {
		t.Fatal("expected not ok for unsafe name")
	}
}
