//go:build linux

package confedit

import (
	"os"
	"path/filepath"
	"strings"
)

// BackupSuffix is what a copy of an edited file is called.
//
// ghostpsy no longer takes such a copy: it installs a file of its own beside the
// distribution's, so an undo is `rm` and there is nothing of this server's to keep.
// The name survives because the by-hand advice tells a person editing the main file
// themselves to take a copy first, and that copy needs a name to suggest.
const BackupSuffix = ".ghostpsy-backup"

// envRoot lets a test redirect the whole /etc tree, so writing and reading real
// files can be exercised without being root and without a real server. Production
// never sets it.
const envRoot = "GHOSTPSY_ETC_ROOT"

// filePath is where this setting's file really is.
func filePath(s Setting) string {
	if root := strings.TrimSpace(os.Getenv(envRoot)); root != "" {
		return filepath.Join(root, s.File)
	}
	return s.File
}

// writeAtomic writes the whole file or none of it.
//
// A half-written sshd_config is a server nobody can log into. The temporary file
// is in the same directory so the rename cannot cross a filesystem, and the
// content is flushed to disk before the rename so a power cut leaves the old file
// rather than an empty one.
func writeAtomic(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".ghostpsy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}
