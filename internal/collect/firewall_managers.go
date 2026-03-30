//go:build linux

package collect

import (
	"os/exec"
	"strings"

	"ghostpsy/agent-linux/internal/payload"
)

func collectFirewallManagers() []payload.FirewallManager {
	firewalldInstalled := commandOnPath("firewall-cmd")
	ufwInstalled := commandOnPath("ufw")

	fd := payload.FirewallManager{Name: "firewalld", Installed: firewalldInstalled}
	if firewalldInstalled {
		fd.Active = firewalldRunning()
	}
	u := payload.FirewallManager{Name: "ufw", Installed: ufwInstalled}
	if ufwInstalled {
		u.Active = ufwStatusActive()
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
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(out))
	return strings.Contains(lower, "status: active")
}
