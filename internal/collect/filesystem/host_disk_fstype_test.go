//go:build linux

package filesystem

import "testing"

func TestShouldSkipHostDiskFstype(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		skip bool
	}{
		{"squashfs", true},
		{"SquashFS", true},
		{" erofs ", true},
		{"ext4", false},
		{"xfs", false},
		{"fuse.snapfuse", false},
	} {
		if got := shouldSkipHostDiskFstype(c.in); got != c.skip {
			t.Fatalf("%q: got %v want %v", c.in, got, c.skip)
		}
	}
}
