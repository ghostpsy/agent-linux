//go:build linux

package shared

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const distroVersionTimeout = 5 * time.Second

// QueryDistroPackageVersion returns the full distro package version for the
// first matching package name (e.g., "2.4.57-2~deb12u2" for apache2 on Debian,
// "2:3.5.25-1.el9" for postfix on RHEL). Tries dpkg-query (Debian/Ubuntu) then
// rpm (RHEL/CentOS). Returns "" on failure.
func QueryDistroPackageVersion(packageNames []string) string {
	for _, name := range packageNames {
		if v := dpkgVersion(name); v != "" {
			return v
		}
		if v := rpmVersion(name); v != "" {
			return v
		}
	}
	return ""
}

func dpkgVersion(pkg string) string {
	if !FileExistsRegular("/usr/bin/dpkg-query") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), distroVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Version}", pkg).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func rpmVersion(pkg string) string {
	if !FileExistsRegular("/usr/bin/rpm") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), distroVersionTimeout)
	defer cancel()
	// %{EPOCHNUM} yields the real epoch (0 when none), so the CVE matcher can align
	// with OSV Red Hat fixed versions that carry an epoch (e.g. postfix "2:3.5.25-1.el9").
	out, err := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", pkg).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if strings.HasPrefix(v, "package") {
		return "" // "package X is not installed"
	}
	return v
}
