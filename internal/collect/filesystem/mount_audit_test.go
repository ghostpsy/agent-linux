//go:build linux

package filesystem

import (
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestLiveMountsFromPartitionStats_joinsOpts(t *testing.T) {
	parts := []disk.PartitionStat{
		{Mountpoint: "/tmp", Opts: []string{"rw", "nosuid", "nodev"}},
		{Mountpoint: "", Opts: []string{"rw"}},
	}
	got := liveMountsFromPartitionStats(parts)
	if len(got) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(got))
	}
	if got[0].mountpoint != "/tmp" || got[0].options != "rw,nosuid,nodev" {
		t.Fatalf("unexpected entry: %+v", got[0])
	}
}

func TestBestProcMountOptions_longestPrefixWins(t *testing.T) {
	mounts := []procMount{
		{mountpoint: "/var", options: "rw"},
		{mountpoint: "/var/lib", options: "rw,nosuid,noexec"},
	}
	if o := bestProcMountOptions("/var/lib/foo", mounts); o != "rw,nosuid,noexec" {
		t.Fatalf("expected /var/lib options, got %q", o)
	}
	if o := bestProcMountOptions("/var/other", mounts); o != "rw" {
		t.Fatalf("expected /var options, got %q", o)
	}
}

func TestLiveMountOptions_usesCache(t *testing.T) {
	mounts := []procMount{{mountpoint: "/tmp", options: "rw,noexec,nodev"}}
	o := liveMountOptions("/tmp", mounts)
	if o.opts != "rw,noexec,nodev" {
		t.Fatalf("got %q", o.opts)
	}
	if liveMountOptions("/none", mounts).opts != "" {
		t.Fatal("expected empty for unknown mount")
	}
}
