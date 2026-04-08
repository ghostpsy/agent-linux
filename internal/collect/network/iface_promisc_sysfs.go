//go:build linux

package network

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// Linux IFF_PROMISC (include/uapi/linux/if.h).
const linuxIFFPromisc = 0x100

func fillIfacePromiscFromSysfs(hn *payload.HostNetwork) {
	for i := range hn.Interfaces {
		p, ok := promiscFromSysfsForIface(hn.Interfaces[i].Name)
		if !ok {
			continue
		}
		hn.Interfaces[i].Promiscuous = &p
	}
}

func promiscFromSysfsForIface(ifname string) (promisc bool, ok bool) {
	if !isSafeSysfsIfaceName(ifname) {
		return false, false
	}
	path := filepath.Join("/sys/class/net", ifname, "flags")
	b, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	return promiscFromSysfsFlagsContent(b), true
}

func isSafeSysfsIfaceName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\x00") {
		return false
	}
	return true
}

func promiscFromSysfsFlagsContent(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return false
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return false
	}
	return v&linuxIFFPromisc != 0
}
