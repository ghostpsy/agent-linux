//go:build linux

package core

import (
	"testing"

	"github.com/shirou/gopsutil/v4/host"
)

func TestPlatformPrettyFromHost_nil(t *testing.T) {
	t.Parallel()
	if got := platformPrettyFromHost(nil); got != "" {
		t.Fatalf("expected empty for nil, got %q", got)
	}
}

func TestPlatformPrettyFromHost_platformAndVersion(t *testing.T) {
	t.Parallel()
	hi := &host.InfoStat{Platform: "ubuntu", PlatformVersion: "22.04"}
	got := platformPrettyFromHost(hi)
	if got != "ubuntu 22.04" {
		t.Fatalf("got %q, want %q", got, "ubuntu 22.04")
	}
}

func TestPlatformPrettyFromHost_platformOnly(t *testing.T) {
	t.Parallel()
	hi := &host.InfoStat{Platform: "centos"}
	got := platformPrettyFromHost(hi)
	if got != "centos" {
		t.Fatalf("got %q, want %q", got, "centos")
	}
}

func TestPlatformPrettyFromHost_emptyPlatform(t *testing.T) {
	t.Parallel()
	hi := &host.InfoStat{PlatformVersion: "22.04"}
	got := platformPrettyFromHost(hi)
	if got != "" {
		t.Fatalf("expected empty for empty platform, got %q", got)
	}
}

func TestPlatformPrettyFromHost_whitespaceHandling(t *testing.T) {
	t.Parallel()
	hi := &host.InfoStat{Platform: "  ubuntu  ", PlatformVersion: " 22.04 "}
	got := platformPrettyFromHost(hi)
	if got != "ubuntu 22.04" {
		t.Fatalf("got %q, want %q", got, "ubuntu 22.04")
	}
}
