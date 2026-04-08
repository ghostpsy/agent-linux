//go:build linux

package filesystem

import "strings"

func mountFlagsFromOptions(opt string) (nodev, nosuid, noexec bool) {
	for _, p := range strings.Split(opt, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		switch p {
		case "nodev":
			nodev = true
		case "nosuid":
			nosuid = true
		case "noexec":
			noexec = true
		}
	}
	return nodev, nosuid, noexec
}
