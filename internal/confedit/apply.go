//go:build linux

package confedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BackupSuffix is what a copy of an edited file is called. One copy per file, and
// it is replaced on every change: an undo means "put back what was there just
// before this job", not "put back some earlier day".
const BackupSuffix = ".ghostpsy-backup"

// envRoot lets a test redirect the whole /etc tree, so the edits below can be
// exercised against real files without being root and without a real server.
// Production never sets it.
const envRoot = "GHOSTPSY_ETC_ROOT"

// filePath is where this setting's file really is.
func filePath(s Setting) string {
	if root := strings.TrimSpace(os.Getenv(envRoot)); root != "" {
		return filepath.Join(root, s.File)
	}
	return s.File
}

// Preview says what would change, and changes nothing.
//
// The output is what the person approving reads, so it shows the file, the line
// as it is now and the line as it would be — not a summary of our own.
func Preview(s Setting, value string) (string, error) {
	content, err := read(filePath(s))
	if err != nil {
		return "", err
	}

	after, changes := Set(s, content, value)
	if !changes {
		return fmt.Sprintf("%s already says %s. Nothing would change.",
			filePath(s), directiveLine(s, value)), nil
	}

	var b strings.Builder
	if _, found := Value(s, content); !found {
		fmt.Fprintf(&b, "%s does not set %s at present, so the built-in default applies.\n\n",
			filePath(s), s.Directive)
	}
	writeSteps(&b, s, false)
	b.WriteString(unifiedDiff(filePath(s), content, after))
	writeRecipe(&b, s, value, content)
	return b.String(), nil
}

// writeSteps lists the operations ghostpsy performs, in the order it performs them.
//
// It exists because the copy-aside used to appear only in the by-hand recipe, under a
// heading saying we do not run those commands — so the one step that makes the change
// reversible looked hypothetical. Every operation we perform has to be visible as ours,
// or "you can see exactly what we do" is not a true claim.
//
// The order is part of the information: the copy exists before the write, which is why
// an undo is always possible.
func writeSteps(b *strings.Builder, s Setting, done bool) {
	path := filePath(s)
	tense := "will do"
	if done {
		tense = "did"
	}

	fmt.Fprintf(b, "ghostpsy does this itself — it %s:\n", tense)
	fmt.Fprintf(b, "  1. copy %s to %s\n", path, path+BackupSuffix)
	fmt.Fprintf(b, "  2. replace %s with the version below, written whole to a temporary file "+
		"in the same directory and then moved into place, so a half-written file is impossible\n\n",
		path)
}

// writeRecipe adds the by-hand version of the change.
//
// It is here rather than left to the screen because only this package knows which
// line is being changed and whether it is already there. A person who wants to check
// what we did, or do it themselves, gets both without asking anybody.
func writeRecipe(b *strings.Builder, s Setting, value, content string) {
	fmt.Fprintf(b, "\n# %s\n", explainWhatWeDid)
	for _, command := range equivalentCommands(s, value, content) {
		fmt.Fprintf(b, "%s\n", command)
	}
}

// Apply takes the copy and makes the change.
//
// The copy comes first and in the same step, so a file this agent changed can
// never have been changed without one. A separate backup step would be a step
// that could be skipped.
func Apply(s Setting, value string) (string, error) {
	content, err := read(filePath(s))
	if err != nil {
		return "", err
	}

	after, changes := Set(s, content, value)
	if !changes {
		return fmt.Sprintf("%s already says %s. Nothing was changed.",
			filePath(s), directiveLine(s, value)), nil
	}

	mode, err := fileMode(filePath(s))
	if err != nil {
		return "", err
	}
	if err := writeAtomic(filePath(s)+BackupSuffix, content, mode); err != nil {
		return "", fmt.Errorf("could not copy %s aside, so nothing was changed: %w", filePath(s), err)
	}
	if err := writeAtomic(filePath(s), after, mode); err != nil {
		return "", fmt.Errorf("could not write %s: %w", filePath(s), err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s now says %s.\n\n", filePath(s), directiveLine(s, value))
	writeSteps(&b, s, true)
	// The diff of what really changed, so the result can be checked against the
	// preview that was approved rather than taken on trust.
	b.WriteString(unifiedDiff(filePath(s), content, after))
	writeRecipe(&b, s, value, content)
	return b.String(), nil
}

// Restore puts back the copy Apply took.
func Restore(s Setting) (string, error) {
	backup := filePath(s) + BackupSuffix
	content, err := os.ReadFile(backup) //nolint:gosec // a declared path, not caller input
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf(
				"there is no copy of %s to put back. Nothing had been changed, or it was already put back",
				filePath(s))
		}
		return "", fmt.Errorf("could not read %s: %w", backup, err)
	}

	mode, err := fileMode(backup)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(filePath(s), string(content), mode); err != nil {
		return "", fmt.Errorf("could not put %s back: %w", filePath(s), err)
	}
	// The copy is removed once it is back in place, so a later undo cannot claim
	// to put back something it already did.
	_ = os.Remove(backup)

	// The undo performs operations too, and they were one sentence before. Both are
	// worth naming: the copy is gone afterwards, which is why a second undo cannot
	// claim to have put anything back.
	return fmt.Sprintf(
		"%s is back to what it was before this job.\n\n"+
			"ghostpsy does this itself — it did:\n"+
			"  1. replace %s with the copy at %s\n"+
			"  2. removed %s, so nothing can claim to put this back twice\n\n"+
			"# The same by hand:\n"+
			"cp %s %s\nrm %s\n%s\n",
		filePath(s),
		filePath(s), backup,
		backup,
		backup, filePath(s), backup,
		strings.Join(checkCommands(s), "\n")), nil
}

// read returns a file's content, treating a missing file as empty.
//
// Missing is normal for the apt one: on a machine that has never had automatic
// updates configured, 20auto-upgrades does not exist, and creating it is exactly
// the fix.
func read(path string) (string, error) {
	content, err := os.ReadFile(path) //nolint:gosec // a declared path, not caller input
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("could not read %s: %w", path, err)
	}
	return string(content), nil
}

// newFileMode is what a config file this agent creates gets. Readable by anyone,
// writable only by root — the same as the distributions' own files.
const newFileMode os.FileMode = 0o644

func fileMode(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newFileMode, nil
		}
		return 0, fmt.Errorf("could not look at %s: %w", path, err)
	}
	return info.Mode().Perm(), nil
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


