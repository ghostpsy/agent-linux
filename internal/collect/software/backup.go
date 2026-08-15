//go:build linux

package software

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

type backupTool struct {
	Name    string
	BinName string
}

var knownBackupTools = []backupTool{
	{Name: "backuppc", BinName: "BackupPC"},
	{Name: "backup-manager", BinName: "backup-manager"},
	{Name: "borg", BinName: "borg"},
	{Name: "restic", BinName: "restic"},
	{Name: "bacula", BinName: "bacula-fd"},
}

var backupKeywordHints = []string{
	"backup",
	"backuppc",
	"backup-manager",
	"borg",
	"restic",
	"bacula",
	"rsync",
	"tar",
	"amanda",
}

var backupDatePaths = []string{
	"/var/archives",
	"/var/lib/BackupPC",
	"/var/lib/bacula",
	"/var/spool/bacula",
	"/backup",
	"/backups",
	"/srv/backup",
	"/var/log/backup.log",
	"/var/log/backup-manager.log",
	"/var/log/borg.log",
	"/var/log/restic.log",
	"/var/log/bacula/bacula.log",
}

// CollectHostBackup detects known backup systems and periodic backup cron hints.
// backup_status is "on" when tools/cron indicate backups likely exist, otherwise "unknown".
func CollectHostBackup(ctx context.Context) *payload.HostBackup {
	tools := detectBackupTools()
	hasCronHint := detectBackupCronHint()
	latest, hasLatest := detectLatestBackupUTC()
	status := "unknown"
	if len(tools) > 0 || hasCronHint {
		status = "on"
	}
	latestUTC := "unknown"
	if hasLatest {
		latestUTC = latest.UTC().Format(time.RFC3339)
	}
	result := &payload.HostBackup{
		BackupStatus:    status,
		LatestBackupUTC: latestUTC,
		ToolsDetected:   tools,
	}
	if len(tools) == 0 {
		result.ToolsDetected = nil
	}
	result.HasPeriodicCron = &hasCronHint
	return result
}

func detectBackupTools() []string {
	out := make([]string, 0, len(knownBackupTools))
	for _, tool := range knownBackupTools {
		if _, err := exec.LookPath(tool.BinName); err == nil {
			out = append(out, tool.Name)
		}
	}
	return out
}

func detectBackupCronHint() bool {
	files := []string{"/etc/crontab"}
	if dirEntries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range dirEntries {
			if entry.IsDir() {
				continue
			}
			files = append(files, filepath.Join("/etc/cron.d", entry.Name()))
		}
	} else if !os.IsNotExist(err) {
		slog.Debug("cannot read /etc/cron.d", "error", err)
	}
	if dirEntries, err := os.ReadDir("/etc/cron.daily"); err == nil {
		for _, entry := range dirEntries {
			if !entry.IsDir() && containsBackupKeyword(entry.Name()) {
				return true
			}
		}
	} else if !os.IsNotExist(err) {
		slog.Debug("cannot read /etc/cron.daily", "error", err)
	}
	for _, file := range files {
		if fileContainsBackupHint(file) {
			return true
		}
	}
	// crontab -u root -l is privileged, and it hid from a search for
	// exec.Command because it lived in this literal table. It now goes through
	// the declared-command path like everything else.
	for _, id := range []privexec.ID{privexec.CrontabListSelf, privexec.CrontabListRoot} {
		res, err := privexec.Run(context.Background(), id)
		out := append(res.Stdout, res.Stderr...)
		if err != nil && len(strings.TrimSpace(string(out))) == 0 {
			slog.Debug("crontab command failed", "command", string(id), "error", err)
			continue
		}
		if textHasBackupHint(string(out)) {
			return true
		}
	}
	return false
}

func detectLatestBackupUTC() (time.Time, bool) {
	var latest time.Time
	found := false
	for _, path := range backupDatePaths {
		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				slog.Debug("cannot stat backup path", "path", path, "error", err)
			}
			continue
		}
		mod := info.ModTime()
		if !found || mod.After(latest) {
			latest = mod
			found = true
		}
	}
	return latest, found
}

func fileContainsBackupHint(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		slog.Debug("cannot open cron file", "path", filePath, "error", err)
		return false
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if textHasBackupHint(line) {
			return true
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Debug("cannot read cron file", "path", filePath, "error", err)
	}
	return false
}

func textHasBackupHint(text string) bool {
	lower := strings.ToLower(text)
	for _, hint := range backupKeywordHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func containsBackupKeyword(name string) bool {
	lower := strings.ToLower(name)
	return slices.ContainsFunc(backupKeywordHints, func(h string) bool {
		return strings.Contains(lower, h)
	})
}
