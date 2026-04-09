//go:build linux

package logging

import (
	"slices"
	"testing"
)

func TestExtractRemoteLogHostsFromRsyslogLine(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"*.* @@log.example.com", []string{"log.example.com"}},
		{"*.* @udp-host.internal", []string{"udp-host.internal"}},
		{"# *.* @@ignored", nil},
		{"", nil},
		{"action(type=\"omfwd\" Target=\"fwd.example\" Port=\"514\")", []string{"fwd.example"}},
		{"*.* @@127.0.0.1", nil},
		{"*.* @@localhost", nil},
	}
	for _, tc := range cases {
		got := extractRemoteLogHostsFromRsyslogLine(tc.line)
		if !slices.Equal(got, tc.want) {
			t.Fatalf("line %q: got %v want %v", tc.line, got, tc.want)
		}
	}
}

func TestExtractRemoteLogHostsFromSyslogNgLine(t *testing.T) {
	line := `destination d_net { tcp("log.ng.example:514" localport(999) ); };`
	got := extractRemoteLogHostsFromSyslogNgLine(line)
	if len(got) != 1 || got[0] != "log.ng.example" {
		t.Fatalf("got %v", got)
	}
}

func TestIsRemoteLogHostToken(t *testing.T) {
	if !isRemoteLogHostToken("log.example.com") {
		t.Fatal("expected true")
	}
	if isRemoteLogHostToken("192.168.1.1") {
		t.Fatal("expected false for IPv4")
	}
	if isRemoteLogHostToken("/dev/console") {
		t.Fatal("expected false for path-like")
	}
}
