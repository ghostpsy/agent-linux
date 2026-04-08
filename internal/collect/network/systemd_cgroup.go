//go:build linux

package network

import (
	"fmt"
	"os"
	"regexp"
)

var cgroupServiceName = regexp.MustCompile(`([a-zA-Z0-9@._-]+\.service)`)

// systemdUnitFromCgroup returns a systemd unit name when the PID cgroup references a .service slice.
func systemdUnitFromCgroup(pid int32) (unit string, ok bool) {
	if pid <= 0 {
		return "", false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	if m := cgroupServiceName.FindStringSubmatch(string(b)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}
