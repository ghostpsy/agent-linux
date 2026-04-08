//go:build linux

package software

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"
)

const installedCountTimeout = 45 * time.Second

// InstalledPackageCountBestEffort counts installed packages when dpkg/rpm/apk/pacman exists (0 if none or on failure).
func InstalledPackageCountBestEffort() int {
	return countInstalledPackageLines()
}

// countInstalledPackageLines returns the number of installed packages (dpkg, rpm, apk, or pacman), or 0 if none apply or on failure.
func countInstalledPackageLines() int {
	switch {
	case fileExists("/usr/bin/dpkg-query"):
		return countFromCommand([]string{"dpkg-query", "-W", "-f", "${Package}\n"})
	case fileExists("/usr/bin/rpm"):
		return countFromCommand([]string{"rpm", "-qa", "--qf", "%{NAME}\n"})
	default:
		if p, err := exec.LookPath("apk"); err == nil {
			return countFromCommand([]string{p, "list", "-I"})
		}
		if fileExists("/usr/bin/pacman") {
			return countFromCommand([]string{"pacman", "-Qq"})
		}
		return 0
	}
}

func countFromCommand(argv []string) int {
	if len(argv) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), installedCountTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0
	}
	if err := cmd.Start(); err != nil {
		return 0
	}
	n := countNonEmptyLinesReader(stdout)
	if err := cmd.Wait(); err != nil {
		return 0
	}
	return n
}

func countNonEmptyLinesReader(r io.Reader) int {
	sc := bufio.NewScanner(r)
	const maxLine = 512
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}
