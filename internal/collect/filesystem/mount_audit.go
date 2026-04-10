//go:build linux

package filesystem

import (
	"context"
	"bufio"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/shirou/gopsutil/v4/disk"
)

// Matches api/ingest.v1.schema.json maxLength for fstab_options / live_mount_options.
const maxMountOptionsSchemaRunes = 512

var mountAuditTargets = []string{"/tmp", "/var", "/home", "/boot", "/dev/shm", "/var/tmp"}

// CollectMountOptionsAudit parses /etc/fstab and live mounts (gopsutil disk.Partitions) for hardening flags.
func CollectMountOptionsAudit(ctx context.Context) *payload.MountOptionsAudit {
	out := &payload.MountOptionsAudit{}
	fstab, err := parseFstabOptions()
	if err != nil {
		out.Error = "fstab could not be read"
		fstab = map[string]string{}
	}
	liveMounts := partitionMountsForAudit()
	for _, mp := range mountAuditTargets {
		sig := payload.MountPathSignals{Mountpoint: mp}
		var fstabOptsFull string
		if opts, ok := fstabMatch(fstab, mp); ok {
			sig.InFstab = true
			fstabOptsFull = opts
		}
		liveOptsFull := liveMountOptions(mp, liveMounts).opts
		nodev, nosuid, noexec := mountFlagsFromOptions(liveOptsFull)
		if liveOptsFull == "" && sig.InFstab {
			nodev, nosuid, noexec = mountFlagsFromOptions(fstabOptsFull)
		}
		sig.Nodev = nodev
		sig.Nosuid = nosuid
		sig.Noexec = noexec
		sig.FstabOptions = shared.TruncateRunes(fstabOptsFull, maxMountOptionsSchemaRunes)
		sig.LiveMountOptions = shared.TruncateRunes(liveOptsFull, maxMountOptionsSchemaRunes)
		out.Paths = append(out.Paths, sig)
	}
	return out
}

func parseFstabOptions() (map[string]string, error) {
	f, err := os.Open("/etc/fstab")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mp := fields[1]
		opts := fields[3]
		if !strings.HasPrefix(mp, "/") {
			continue
		}
		m[mp] = opts
	}
	if err := sc.Err(); err != nil {
		return m, err
	}
	return m, nil
}

type procMount struct {
	mountpoint string
	options    string
}

func partitionMountsForAudit() []procMount {
	parts, err := disk.Partitions(true)
	if err != nil {
		return nil
	}
	return liveMountsFromPartitionStats(parts)
}

func liveMountsFromPartitionStats(parts []disk.PartitionStat) []procMount {
	out := make([]procMount, 0, len(parts))
	for _, p := range parts {
		if p.Mountpoint == "" {
			continue
		}
		out = append(out, procMount{mountpoint: p.Mountpoint, options: strings.Join(p.Opts, ",")})
	}
	return out
}

func fstabMatch(fstab map[string]string, target string) (opts string, ok bool) {
	if o, hit := fstab[target]; hit {
		return o, true
	}
	var best string
	bestLen := -1
	for mp, o := range fstab {
		if target == mp || strings.HasPrefix(target, mp+"/") {
			if len(mp) > bestLen {
				bestLen = len(mp)
				best = o
			}
		}
	}
	if bestLen >= 0 {
		return best, true
	}
	return "", false
}

type liveOpts struct {
	opts string
}

func liveMountOptions(target string, cached []procMount) liveOpts {
	if len(cached) == 0 {
		return liveOpts{}
	}
	if o := bestProcMountOptions(target, cached); o != "" {
		return liveOpts{opts: o}
	}
	return liveOpts{}
}

func bestProcMountOptions(target string, mounts []procMount) string {
	var best string
	bestLen := -1
	for _, m := range mounts {
		mp := m.mountpoint
		if target == mp || strings.HasPrefix(target, mp+"/") {
			if len(mp) > bestLen {
				bestLen = len(mp)
				best = m.options
			}
		}
	}
	return best
}
