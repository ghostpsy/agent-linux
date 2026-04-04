//go:build linux

package firewall

import (
	"os"
	"os/exec"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func collectFirewallManagers() []payload.FirewallManager {
	firewalldInstalled := commandOnPath("firewall-cmd")
	ufwBin := ufwExecutablePath()
	ufwInstalled := ufwBin != ""

	fd := payload.FirewallManager{Name: "firewalld", Installed: firewalldInstalled}
	if firewalldInstalled {
		fd.Active = firewalldRunning()
	}
	u := payload.FirewallManager{Name: "ufw", Installed: ufwInstalled}
	if ufwInstalled {
		u.Active = ufwStatusActiveWithPath(ufwBin) || ufwEnabledInConf()
	}
	return []payload.FirewallManager{fd, u}
}

func commandOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func firewalldRunning() bool {
	out, err := exec.Command("firewall-cmd", "--state").Output()
	return err == nil && strings.TrimSpace(strings.ToLower(string(out))) == "running"
}

func ufwStatusActive() bool {
	return ufwStatusActiveWithPath(ufwExecutablePath())
}

// ufwPersistedEnabled is true when the ufw CLI exists and /etc/ufw/ufw.conf sets ENABLED=yes.
// `ufw status` often fails or mis-parses under minimal PATH/locale; persisted config matches audit images.
func ufwPersistedEnabled() bool {
	if ufwExecutablePath() == "" {
		return false
	}
	return ufwEnabledInConf()
}

func ufwEnabledFromConfContent(content string) bool {
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(strings.ToLower(parts[0])) != "enabled" {
			continue
		}
		val := strings.TrimSpace(strings.ToLower(parts[1]))
		return val == "yes" || val == "true"
	}
	return false
}

func ufwEnabledInConf() bool {
	data, err := os.ReadFile("/etc/ufw/ufw.conf")
	if err != nil {
		return false
	}
	return ufwEnabledFromConfContent(string(data))
}

func ufwExecutablePath() string {
	if p, err := exec.LookPath("ufw"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/ufw", "/sbin/ufw"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func ufwStatusMeansActive(statusOutputLower string) bool {
	if strings.Contains(statusOutputLower, "status: inactive") {
		return false
	}
	if strings.Contains(statusOutputLower, "status: active") {
		return true
	}
	return strings.Contains(statusOutputLower, "firewall is active") || strings.Contains(statusOutputLower, "firewall loaded")
}

func ufwStatusActiveWithPath(ufwPath string) bool {
	if ufwPath == "" {
		return false
	}
	out, err := exec.Command(ufwPath, "status").Output()
	if err != nil {
		return false
	}
	return ufwStatusMeansActive(strings.ToLower(string(out)))
}
