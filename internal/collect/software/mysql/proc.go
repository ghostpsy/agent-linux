//go:build linux

package mysql

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

func discoverMysqldDefaultsFileFromProc() string {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		commPath := filepath.Join("/proc", pid, "comm")
		b, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		if name != "mysqld" && name != "mariadbd" {
			continue
		}
		cmdPath := filepath.Join("/proc", pid, "cmdline")
		raw, err := os.ReadFile(cmdPath)
		if err != nil || len(raw) == 0 {
			continue
		}
		args := bytes.Split(raw, []byte{0})
		for _, a := range args {
			s := string(a)
			if strings.HasPrefix(s, "--defaults-file=") {
				return strings.TrimPrefix(s, "--defaults-file=")
			}
		}
	}
	return ""
}

func discoverMysqldProcUID() (uid int, ok bool) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		commPath := filepath.Join("/proc", pid, "comm")
		b, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		if name != "mysqld" && name != "mariadbd" {
			continue
		}
		stPath := filepath.Join("/proc", pid, "status")
		sb, err := os.ReadFile(stPath)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(sb), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					u, err := strconv.Atoi(fields[1])
					if err == nil {
						return u, true
					}
				}
				break
			}
		}
	}
	return 0, false
}

func procUsernameForUID(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.Username
}

func filePermissionSummary(path string) *string {
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	mode := st.Mode().Perm()
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		s := fmt.Sprintf("%04o", mode&0o777)
		return shared.StringPtr(s + " (owner lookup unavailable)")
	}
	uname := procUsernameForUID(int(sys.Uid))
	gname := ""
	if g, err := user.LookupGroupId(strconv.Itoa(int(sys.Gid))); err == nil {
		gname = g.Name
	}
	s := fmt.Sprintf("%04o %s %s", mode&0o777, uname, gname)
	if uname == "" {
		s = fmt.Sprintf("%04o uid:%d gid:%d", mode&0o777, sys.Uid, sys.Gid)
	}
	return shared.StringPtr(strings.TrimSpace(s))
}
