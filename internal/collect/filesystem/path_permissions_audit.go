//go:build linux

package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	maxWorldWritableDirs = 24
	maxSgidItems         = 32
	maxUnownedPaths      = 24
	sgidScanTimeout      = 3 * time.Second
)

// CollectPathPermissionsAudit samples world-writable dirs, /tmp sticky, SGID files, and unowned paths (bounded).
func CollectPathPermissionsAudit() *payload.PathPermissionsAudit {
	out := &payload.PathPermissionsAudit{}
	if fi, err := os.Stat("/tmp"); err == nil {
		m := fi.Mode()
		t := m&os.ModeSticky != 0
		out.TmpStickyBitPresent = &t
	}
	out.WorldWritableDirsSample = findWorldWritableDirsSample()
	out.SgidItemsSample = collectSgidSample()
	out.UnownedFilesSample = findUnownedFilesSample()
	return out
}

func findWorldWritableDirsSample() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "find", "/tmp", "/var/tmp", "-xdev", "-maxdepth", "2", "-type", "d", "-perm", "-002")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= maxWorldWritableDirs {
			break
		}
	}
	return lines
}

func collectSgidSample() []payload.SgidItem {
	out := []payload.SgidItem{}
	ctx, cancel := context.WithTimeout(context.Background(), sgidScanTimeout)
	defer cancel()
	for _, root := range suidFindRoots {
		if len(out) >= maxSgidItems {
			break
		}
		if ctx.Err() != nil {
			break
		}
		ri, err := os.Stat(root)
		if err != nil {
			continue
		}
		rst, ok := ri.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		rootDev := rst.Dev
		_ = filepath.WalkDir(root, sgidWalkFunc(ctx, rootDev, &out))
	}
	return out
}

func sgidWalkFunc(ctx context.Context, rootDev uint64, out *[]payload.SgidItem) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if err != nil {
			return nil
		}
		if len(*out) >= maxSgidItems {
			return fs.SkipAll
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if st.Dev != rootDev {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			return nil
		}
		owner := strconv.FormatUint(uint64(st.Uid), 10)
		if u, err := user.LookupId(owner); err == nil {
			owner = u.Username
		}
		modeStr := fmt.Sprintf("%04o", uint32(fi.Mode())&0o7777)
		*out = append(*out, payload.SgidItem{Path: path, Owner: owner, Mode: modeStr})
		if len(*out) >= maxSgidItems {
			return fs.SkipAll
		}
		return nil
	}
}

func findUnownedFilesSample() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "find", "/tmp", "/var/tmp", "-xdev", "-maxdepth", "3", "(", "-nouser", "-o", "-nogroup", ")")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= maxUnownedPaths {
			break
		}
	}
	return lines
}
