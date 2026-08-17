//go:build linux

package action

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// FreeBytes reports the space left on the filesystem holding path.
//
// Bavail, not Bfree: Bfree counts blocks the kernel keeps for root, and writing
// into those is how a "successful" backup leaves a disk with nothing left for
// anybody else.
func FreeBytes(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("could not measure the free space on %s: %w", path, err)
	}
	//nolint:gosec // Bavail and Bsize are non-negative sizes from the kernel
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
