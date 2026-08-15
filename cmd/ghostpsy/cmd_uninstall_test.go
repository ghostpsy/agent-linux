//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uninstallFixture(t *testing.T) (root string, paths uninstallPaths) {
	t.Helper()
	root = t.TempDir()
	paths = uninstallPaths{
		Binary:  filepath.Join(root, "usr/local/bin/ghostpsy"),
		Sudoers: filepath.Join(root, "etc/sudoers.d/ghostpsy"),
		Config:  filepath.Join(root, "etc/ghostpsy"),
		State:   filepath.Join(root, "var/lib/ghostpsy"),
	}
	for _, p := range []string{paths.Binary, paths.Sudoers} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{paths.Config, paths.State} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, paths
}

// Without --purge the machine keeps its identity, so a reinstall does not
// appear in the dashboard as a second, unrelated server.
func TestUninstallKeepsConfigAndStateByDefault(t *testing.T) {
	_, paths := uninstallFixture(t)

	removed, err := removeInstalledFiles(paths, false)
	if err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	if _, err := os.Stat(paths.Binary); !os.IsNotExist(err) {
		t.Error("the binary should have been removed")
	}
	if _, err := os.Stat(paths.Config); os.IsNotExist(err) {
		t.Error("the config must be kept without --purge")
	}
	if strings.Contains(strings.Join(removed, " "), paths.State) {
		t.Errorf("state must not be reported as removed without --purge: %v", removed)
	}
}

// With --purge, nothing of ghostpsy may be left. The mockup promises exactly
// that, and a tool that is hard to remove is a tool people hesitate to install.
func TestPurgeLeavesNothingBehind(t *testing.T) {
	_, paths := uninstallFixture(t)

	removed, err := removeInstalledFiles(paths, true)
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}

	for _, p := range []string{paths.Binary, paths.Sudoers, paths.Config, paths.State} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived --purge", p)
		}
	}
	if len(removed) < 4 {
		t.Errorf("expected every removed path to be reported, got %v", removed)
	}
}

// Removing something already gone is not a failure. Uninstall has to finish
// whatever state it finds, or it leaves the host half-cleaned.
func TestUninstallSucceedsWhenNothingIsInstalled(t *testing.T) {
	root := t.TempDir()
	paths := uninstallPaths{
		Binary:  filepath.Join(root, "nope/ghostpsy"),
		Sudoers: filepath.Join(root, "nope/sudoers"),
		Config:  filepath.Join(root, "nope/config"),
		State:   filepath.Join(root, "nope/state"),
	}

	removed, err := removeInstalledFiles(paths, true)

	if err != nil {
		t.Fatalf("uninstall on a clean host must succeed, got: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("nothing was installed, so nothing should be reported: %v", removed)
	}
}

// Found on a real host: the binary could not be removed, and uninstall stopped
// there — leaving the sudo rule installed. A privilege grant for a tool you
// just uninstalled is the worst possible leftover, so it goes first and one
// failure must not stop the rest.
func TestUninstallRemovesTheSudoRuleBeforeTheBinary(t *testing.T) {
	_, paths := uninstallFixture(t)

	removed, _ := removeInstalledFiles(paths, false)

	if len(removed) == 0 {
		t.Fatal("nothing was removed")
	}
	if removed[0] != paths.Sudoers {
		t.Fatalf("the sudo rule must be removed first, order was: %v", removed)
	}
}

func TestUninstallKeepsGoingWhenOnePathCannotBeRemoved(t *testing.T) {
	_, paths := uninstallFixture(t)
	// The binary refuses to go, exactly as it did on a real host where it was
	// still mapped: "device or resource busy".
	stuck := func(p string) error {
		if p == paths.Binary {
			return errors.New("device or resource busy")
		}
		return os.RemoveAll(p)
	}

	removed, err := removeInstalledFilesWith(paths, true, stuck)

	if err == nil {
		t.Fatal("expected the failure to be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), paths.Binary) {
		t.Errorf("the error must name what was left behind, got: %v", err)
	}
	for _, want := range []string{paths.Sudoers, paths.Config, paths.State} {
		if !strings.Contains(strings.Join(removed, " "), want) {
			t.Errorf("%s should still have been removed, got: %v", want, removed)
		}
	}
}
