//go:build linux

package postgres

import (
	"testing"
)

func TestListenAddressesImpliesAll(t *testing.T) {
	t.Parallel()
	if !listenAddressesImpliesAll("*") || !listenAddressesImpliesAll("0.0.0.0") {
		t.Fatal("wildcard binds")
	}
	if !listenAddressesImpliesAll("127.0.0.1, ::") {
		t.Fatal("comma list with :: should imply all")
	}
	if listenAddressesImpliesAll("127.0.0.1") {
		t.Fatal("localhost only")
	}
}

func TestAnalyzePgHba(t *testing.T) {
	t.Parallel()
	body := `# TYPE DATABASE USER ADDRESS METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
hostssl all             all             0.0.0.0/0               trust
`
	ho := hbaAnalyze(body)
	if ho.localN != 1 || ho.host != 1 || ho.hostssl != 1 {
		t.Fatalf("counts local=%d host=%d hostssl=%d", ho.localN, ho.host, ho.hostssl)
	}
	if ho.trustN != 1 || ho.scramN != 1 || ho.peerIdentN != 1 {
		t.Fatalf("methods trust=%d scram=%d peer=%d", ho.trustN, ho.scramN, ho.peerIdentN)
	}
}
