//go:build linux

package shared

import "os"

// FileExistsRegular reports whether path exists and is not a directory.
func FileExistsRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
