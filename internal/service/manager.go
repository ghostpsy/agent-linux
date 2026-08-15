//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const (
	unitName        = "ghostpsy"
	systemdUnitPath = "/etc/systemd/system/ghostpsy.service"
	upstartJobPath  = "/etc/init/ghostpsy.conf"
)

// Manager installs and removes the agent's service on one init system.
type Manager interface {
	Install(Spec) error
	Remove() error
}

type runFn func(name string, args ...string) error
type writeFn func(path, content string) error
type removeFn func(path string) error

// For returns the manager for this host, or an error naming what is missing.
// A host with no recognised init system is told plainly rather than given a
// service definition it will never read.
func For(kind Kind) (Manager, error) {
	switch kind {
	case Systemd:
		return systemdManager{run: runCommand, write: writeFile, remove: os.Remove}, nil
	case Upstart:
		return upstartManager{run: runCommand, write: writeFile, remove: os.Remove}, nil
	default:
		return nil, errors.New("this server does not use systemd or Upstart, so ghostpsy cannot install itself as a service here")
	}
}

type systemdManager struct {
	run    runFn
	write  writeFn
	remove removeFn
}

func (m systemdManager) Install(s Spec) error {
	if err := m.write(systemdUnitPath, systemdUnit(s)); err != nil {
		return fmt.Errorf("could not write the service file: %w", err)
	}
	// daemon-reload first: enable acts on a unit systemd has not read yet
	// otherwise, and reports success while doing nothing.
	if err := m.run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("could not reload systemd: %w", err)
	}
	if err := m.run("systemctl", "enable", "--now", unitName); err != nil {
		return fmt.Errorf("could not start the ghostpsy service: %w", err)
	}
	return nil
}

func (m systemdManager) Remove() error {
	// Stopping something already stopped is not a failure. Removal has to
	// finish whatever state it finds, or it leaves the host half-cleaned.
	_ = m.run("systemctl", "stop", unitName)
	_ = m.run("systemctl", "disable", unitName)
	if err := m.remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not remove the service file: %w", err)
	}
	_ = m.run("systemctl", "daemon-reload")
	return nil
}

type upstartManager struct {
	run    runFn
	write  writeFn
	remove removeFn
}

func (m upstartManager) Install(s Spec) error {
	if err := m.write(upstartJobPath, upstartJob(s)); err != nil {
		return fmt.Errorf("could not write the service file: %w", err)
	}
	if err := m.run("initctl", "start", unitName); err != nil {
		return fmt.Errorf("could not start the ghostpsy service: %w", err)
	}
	return nil
}

func (m upstartManager) Remove() error {
	_ = m.run("initctl", "stop", unitName)
	if err := m.remove(upstartJobPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not remove the service file: %w", err)
	}
	return nil
}

func runCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
