//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	envSystemdDirOverride = "GHOSTPSY_SYSTEMD_DIR"
	envCronFileOverride   = "GHOSTPSY_CRON_FILE"
	envSelfPathOverride   = "GHOSTPSY_SELF_PATH"

	defaultSystemdDir = "/etc/systemd/system"
	defaultCronFile   = "/etc/cron.d/ghostpsy"
	systemdMarker     = "/run/systemd/system"

	systemdServiceName = "ghostpsy.service"
	systemdTimerName   = "ghostpsy.timer"
)

// scheduleSpec maps a friendly schedule name to systemd OnCalendar and
// cron expressions. We deliberately keep the set small and predictable;
// users with unusual cadences can edit the generated files by hand.
type scheduleSpec struct {
	name       string
	onCalendar string
	cronExpr   string
}

var supportedSchedules = []scheduleSpec{
	{"hourly", "hourly", "0 * * * *"},
	{"daily", "*-*-* 03:00:00", "0 3 * * *"},
	{"weekly", "Sun *-*-* 03:00:00", "0 3 * * 0"},
	{"monthly", "*-*-01 03:00:00", "0 3 1 * *"},
}

func lookupSchedule(name string) (scheduleSpec, error) {
	for _, s := range supportedSchedules {
		if s.name == name {
			return s, nil
		}
	}
	names := make([]string, 0, len(supportedSchedules))
	for _, s := range supportedSchedules {
		names = append(names, s.name)
	}
	return scheduleSpec{}, fmt.Errorf("unknown schedule %q (supported: %s)", name, strings.Join(names, ", "))
}

func newCronCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cron",
		Short: "Install, remove, or inspect the scheduled-scan timer.",
		Long: `cron manages scheduled scans on this host.

Prefers a systemd timer when systemd is detected, falling back to a single
/etc/cron.d/ghostpsy entry. The schedule is one of: hourly, daily, weekly
(default), monthly.`,
	}
	cmd.AddCommand(newCronInstallCommand())
	cmd.AddCommand(newCronRemoveCommand())
	cmd.AddCommand(newCronStatusCommand())
	return cmd
}

func newCronInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the scheduled-scan timer.",
		Run:   runCronInstall,
	}
	cmd.Flags().String("schedule", "weekly", "scan schedule (hourly|daily|weekly|monthly)")
	return cmd
}

func newCronRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Remove the installed scheduled-scan timer.",
		Run:   runCronRemove,
	}
}

func newCronStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print which scheduled-scan mechanism is installed.",
		Run:   runCronStatus,
	}
}

func runCronInstall(cmd *cobra.Command, _ []string) {
	scheduleName, err := cmd.Flags().GetString("schedule")
	if err != nil {
		printErrorLine("cron install: invalid flags")
		os.Exit(1)
	}
	spec, err := lookupSchedule(scheduleName)
	if err != nil {
		printErrorLine("cron install: " + err.Error())
		os.Exit(1)
	}
	selfPath, err := resolveSelfPath()
	if err != nil {
		printErrorLine(fmt.Sprintf("cron install: resolve binary path: %v", err))
		os.Exit(1)
	}

	if useSystemd() {
		if err := installSystemdUnits(spec, selfPath); err != nil {
			printErrorLine(fmt.Sprintf("cron install: %v", err))
			os.Exit(1)
		}
		printSuccessLine("Installed systemd timer (" + scheduleName + "). Run `systemctl status ghostpsy.timer` to inspect.")
		return
	}
	if err := installCronEntry(spec, selfPath); err != nil {
		printErrorLine(fmt.Sprintf("cron install: %v", err))
		os.Exit(1)
	}
	printSuccessLine("Installed cron entry at " + cronFilePath() + " (" + scheduleName + ").")
}

func runCronRemove(_ *cobra.Command, _ []string) {
	removed := false
	if useSystemd() {
		if err := removeSystemdUnits(); err != nil {
			printErrorLine(fmt.Sprintf("cron remove: %v", err))
			os.Exit(1)
		}
		removed = true
	}
	if _, err := os.Stat(cronFilePath()); err == nil {
		if err := os.Remove(cronFilePath()); err != nil {
			printErrorLine(fmt.Sprintf("cron remove: %v", err))
			os.Exit(1)
		}
		removed = true
	}
	if !removed {
		printMutedLine("No scheduled-scan mechanism was installed.")
		return
	}
	printSuccessLine("Scheduled-scan timer removed.")
}

func runCronStatus(_ *cobra.Command, _ []string) {
	servicePath := filepath.Join(systemdDir(), systemdServiceName)
	timerPath := filepath.Join(systemdDir(), systemdTimerName)
	if useSystemd() {
		if _, err := os.Stat(timerPath); err == nil {
			fmt.Println("Systemd timer installed:", timerPath)
			fmt.Println("Service file:        ", servicePath)
			return
		}
	}
	if _, err := os.Stat(cronFilePath()); err == nil {
		fmt.Println("Cron entry installed:", cronFilePath())
		return
	}
	fmt.Println("No scheduled-scan mechanism installed.")
}

func useSystemd() bool {
	if _, err := os.Stat(systemdMarker); err == nil {
		return true
	}
	return false
}

func systemdDir() string {
	if v := strings.TrimSpace(os.Getenv(envSystemdDirOverride)); v != "" {
		return v
	}
	return defaultSystemdDir
}

func cronFilePath() string {
	if v := strings.TrimSpace(os.Getenv(envCronFileOverride)); v != "" {
		return v
	}
	return defaultCronFile
}

func resolveSelfPath() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envSelfPathOverride)); v != "" {
		return v, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if abs, err := filepath.EvalSymlinks(p); err == nil {
		return abs, nil
	}
	return p, nil
}

func renderSystemdService(selfPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Ghostpsy scheduled scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s scan --yes
`, selfPath)
}

func renderSystemdTimer(spec scheduleSpec) string {
	return fmt.Sprintf(`[Unit]
Description=Run Ghostpsy scan on a %s schedule

[Timer]
OnCalendar=%s
Persistent=true
RandomizedDelaySec=300
Unit=%s

[Install]
WantedBy=timers.target
`, spec.name, spec.onCalendar, systemdServiceName)
}

func renderCronEntry(spec scheduleSpec, selfPath string) string {
	return fmt.Sprintf("# Ghostpsy scheduled scan (%s)\n%s root %s scan --yes\n",
		spec.name, spec.cronExpr, selfPath)
}

func installSystemdUnits(spec scheduleSpec, selfPath string) error {
	dir := systemdDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	servicePath := filepath.Join(dir, systemdServiceName)
	timerPath := filepath.Join(dir, systemdTimerName)
	if err := os.WriteFile(servicePath, []byte(renderSystemdService(selfPath)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", servicePath, err)
	}
	if err := os.WriteFile(timerPath, []byte(renderSystemdTimer(spec)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", timerPath, err)
	}
	if !skipSystemctl() {
		if err := runSystemctl("daemon-reload"); err != nil {
			return err
		}
		if err := runSystemctl("enable", "--now", systemdTimerName); err != nil {
			return err
		}
	}
	return nil
}

func removeSystemdUnits() error {
	dir := systemdDir()
	servicePath := filepath.Join(dir, systemdServiceName)
	timerPath := filepath.Join(dir, systemdTimerName)
	if !skipSystemctl() {
		// Best-effort: ignore failures so a partial install can still be cleaned up.
		_ = runSystemctl("disable", "--now", systemdTimerName)
	}
	for _, p := range []string{timerPath, servicePath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	if !skipSystemctl() {
		_ = runSystemctl("daemon-reload")
	}
	return nil
}

func installCronEntry(spec scheduleSpec, selfPath string) error {
	p := cronFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(renderCronEntry(spec, selfPath)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}

// skipSystemctl returns true when tests have overridden the systemd dir,
// so the test process never shells out to systemctl on the host.
func skipSystemctl() bool {
	return strings.TrimSpace(os.Getenv(envSystemdDirOverride)) != ""
}

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
