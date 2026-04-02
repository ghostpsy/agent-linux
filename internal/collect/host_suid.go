//go:build linux

package collect

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"ghostpsy/agent-linux/internal/payload"
)

const maxSuidItems = 64

var suidFindRoots = []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/local/bin"}

// CollectHostSuid lists setuid binaries under common roots (bounded).
// Implemented with filepath.WalkDir (no external find): gopsutil does not expose filesystem setuid enumeration.
func CollectHostSuid() *payload.HostSuid {
	out := &payload.HostSuid{Items: []payload.SuidItem{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, root := range suidFindRoots {
		if len(out.Items) >= maxSuidItems {
			break
		}
		if ctx.Err() != nil {
			out.Error = "setuid scan timed out"
			return out
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
		_ = filepath.WalkDir(root, suidWalkFunc(ctx, rootDev, out))
	}
	if ctx.Err() != nil && out.Error == "" {
		out.Error = "setuid scan timed out"
	}
	return out
}

func suidWalkFunc(ctx context.Context, rootDev uint64, out *payload.HostSuid) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			out.Error = "setuid scan timed out"
			return fs.SkipAll
		}
		if err != nil {
			return nil
		}
		if len(out.Items) >= maxSuidItems {
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
		if fi.Mode()&os.ModeSetuid == 0 {
			return nil
		}
		item, ok := suidItemFromFileInfo(path, fi)
		if !ok {
			return nil
		}
		out.Items = append(out.Items, item)
		if len(out.Items) >= maxSuidItems {
			return fs.SkipAll
		}
		return nil
	}
}

func suidItemFromFileInfo(path string, fi os.FileInfo) (payload.SuidItem, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return payload.SuidItem{}, false
	}
	mode := fi.Mode()
	owner := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(owner); err == nil {
		owner = u.Username
	}
	modeStr := fmt.Sprintf("%04o", uint32(mode)&0o7777)
	return payload.SuidItem{Path: path, Owner: owner, Mode: modeStr}, true
}
