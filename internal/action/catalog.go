//go:build linux

package action

import (
	"regexp"
	"time"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// The first four fixes ghostpsy can make. Best practice first, and the order is
// the point.
//
// Our competitors work from a list: a database of known holes and a patch
// catalogue. They can tell a customer a package is out of date. They cannot tell
// them their firewall is off, or that automatic security updates were never
// switched on, or that their SSH settings are weak — none of those has a number in
// anybody's database, so their list does not contain them.
//
// This agent already collects all of that. It just never acted on it.
//
// So these four are the most different from what else exists, the cheapest to
// build, and the safest to ship first: a config change can be put back byte for
// byte, and deleting logs cannot. It is rare for "most different" and "safest" to
// be the same choice. When it happens, start there.
//
// Disk cleanup and package updates come next (#183), on the runtime this file
// already sits on.

func init() {
	declare(enableFirewall())
	declare(enableAutomaticSecurityUpdates())
	declare(hardenSSHConfig())
	declare(restartFailedService())
}

// sshPortParam is the port the operator reaches this machine on.
//
// It is a parameter rather than a guess at 22, because a server whose SSH moved to
// 2222 is exactly the server where guessing locks somebody out.
var sshPortParam = Param{
	Name:  "ssh_port",
	Why:   "the port you reach this machine on over SSH",
	Allow: regexp.MustCompile(`^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`),
}

// enableFirewall switches on a firewall that is off.
//
// The entire risk of this action is one sentence: switching on a firewall on a
// remote server is how people lose access to their own machine for good. Three
// things stand against that, and all three are needed.
//
//  1. The port is allowed *before* the firewall goes on, never after.
//  2. The dry run's own output is read, and the plan is refused if the rules it
//     would install do not cover a port somebody is connected on right now.
//  3. If the machine stops answering anyway, the firewall is switched back off
//     without waiting to be asked.
func enableFirewall() Action {
	return Action{
		Type: "enable_firewall",
		Summary: "Switch on the firewall, allowing port {ssh_port} first so you do not " +
			"lose access to this machine.",
		Params:        []Param{sshPortParam},
		Reversibility: ReverseFull,
		UndoWhy: "The firewall is switched off again, back to how this machine was before. " +
			"The rules it already had are left exactly as they were.",
		Variants: []Variant{
			{
				// Debian and Ubuntu. ufw --dry-run is a real dry run: it prints
				// the exact rules it would install, which is what makes check 2
				// above possible at all.
				Needs: "ufw",
				DryRun: []Step{
					{
						Why:     "show the rule that keeps your way in open",
						Command: privexec.UfwDryRunAllowPort,
						Args:    map[string]string{"port": "{ssh_port}"},
					},
					{
						Why:     "show every rule switching the firewall on would install",
						Command: privexec.UfwDryRunEnable,
					},
					{
						Why:   "make sure those rules do not cut off the way you are connected now",
						Check: CheckPlanKeepsMeReachable,
					},
					{
						Why:     "show the firewall as it is now",
						Command: privexec.FirewallUfwStatusVerbose,
					},
				},
				Run: []Step{
					{
						// First, always. The order is the safety.
						Why:     "allow your way in through the firewall",
						Command: privexec.UfwAllowPort,
						Args:    map[string]string{"port": "{ssh_port}"},
					},
					{
						Why:     "switch the firewall on",
						Command: privexec.UfwEnable,
					},
				},
				Verify: []Step{
					{
						Why:     "check the firewall is on and read back its rules",
						Command: privexec.FirewallUfwStatusVerbose,
					},
					{
						Why:   "check this machine is still answering on the port you use",
						Check: CheckKeepsMeReachable,
					},
				},
				Undo: []Step{
					{
						Why:     "switch the firewall off again",
						Command: privexec.UfwDisable,
					},
				},
			},
			{
				// The RHEL family. firewalld has no dry run, so the preview shows
				// what is configured now, and safety comes from the order: the
				// port is added to the permanent rules before the firewall starts.
				Needs: "firewall-cmd",
				DryRun: []Step{
					{
						Why:     "show whether the firewall is running",
						Command: privexec.FirewalldState,
					},
					{
						Why:     "show the rules as they are now",
						Command: privexec.FirewalldListAll,
					},
				},
				Run: []Step{
					{
						Why:     "allow your way in, before the firewall starts",
						Command: privexec.FirewalldAddPort,
						Args:    map[string]string{"port": "{ssh_port}"},
					},
					{
						Why:     "start the firewall and make it start at boot",
						Command: privexec.ServiceEnableNow,
						Args:    map[string]string{"unit": "firewalld"},
					},
					{
						Why:     "make the firewall read the rules it was just given",
						Command: privexec.FirewalldReload,
					},
				},
				Verify: []Step{
					{
						Why:     "read back which ports the running firewall allows",
						Command: privexec.FirewalldRuntimePorts,
					},
					{
						Why:   "check this machine is still answering on the port you use",
						Check: CheckKeepsMeReachable,
					},
				},
				Undo: []Step{
					{
						Why:     "stop the firewall again",
						Command: privexec.ServiceDisableNow,
						Args:    map[string]string{"unit": "firewalld"},
					},
					{
						Why:     "take the port rule back out",
						Command: privexec.FirewalldRemovePort,
						Args:    map[string]string{"port": "{ssh_port}"},
					},
				},
			},
		},
	}
}

// enableAutomaticSecurityUpdates is the highest-value action in the catalog.
//
// Everything else here is work: it fixes one problem that already exists. This one
// removes work — it stops future problems from appearing at all. A machine that
// installs its own security updates does not need us to notice them.
func enableAutomaticSecurityUpdates() Action {
	return Action{
		Type: "enable_automatic_security_updates",
		Summary: "Switch on automatic security updates, so this machine installs them " +
			"itself instead of waiting to be noticed.",
		Reversibility: ReverseFull,
		UndoWhy: "The settings file is put back byte for byte from the copy taken before " +
			"it was edited.",
		Variants: []Variant{
			{
				// Debian and Ubuntu. unattended-upgrades has a genuine dry run
				// that lists what it would install, which is exactly what the
				// person approving needs to see.
				Needs:  "unattended-upgrade",
				Backup: BackupPlan{Kind: BackupCopyFiles, Target: "/etc/apt/apt.conf.d/20auto-upgrades"},
				DryRun: []Step{
					{
						Why:     "show the change that makes the machine check daily",
						Command: privexec.ConfigPreview,
						Args:    map[string]string{"key": "apt.update_package_lists", "value": "1"},
					},
					{
						Why:     "show the change that makes it install security updates",
						Command: privexec.ConfigPreview,
						Args:    map[string]string{"key": "apt.unattended_upgrade", "value": "1"},
					},
					{
						Why:     "show which updates it would install in future. Nothing is installed now",
						Command: privexec.UnattendedUpgradeDryRun,
					},
				},
				Run: []Step{
					{
						Why:     "make the machine check daily for new packages",
						Command: privexec.ConfigApply,
						Args:    map[string]string{"key": "apt.update_package_lists", "value": "1"},
					},
					{
						Why:     "make the machine install security updates on its own",
						Command: privexec.ConfigApply,
						Args:    map[string]string{"key": "apt.unattended_upgrade", "value": "1"},
					},
					{
						Why:     "start the service that does the work",
						Command: privexec.ServiceEnableNow,
						Args:    map[string]string{"unit": "unattended-upgrades"},
					},
				},
				Verify: []Step{
					{
						Why:     "ask apt whether it really has the setting now",
						Command: privexec.ConfigVerify,
						Args:    map[string]string{"key": "apt.unattended_upgrade", "value": "1"},
					},
					{
						Why:     "check a full update cycle would now succeed",
						Command: privexec.UnattendedUpgradeDryRun,
					},
				},
				Undo: []Step{
					{
						Why:     "put the settings file back",
						Command: privexec.ConfigRestore,
						Args:    map[string]string{"key": "apt.unattended_upgrade"},
					},
				},
			},
			{
				// The RHEL family. dnf-automatic is driven by a timer, and there
				// is no config file to edit, so there is nothing to copy aside
				// either — switching the timer off again is the whole undo.
				Needs: "/usr/bin/dnf-automatic",
				DryRun: []Step{
					{
						Why:     "show whether the update timer is on today",
						Command: privexec.ServiceIsEnabled,
						Args:    map[string]string{"unit": "dnf-automatic.timer"},
					},
					{
						Why:     "show the machine's scheduled jobs, so you can see where this would sit",
						Command: privexec.SystemdListTimers,
					},
				},
				Run: []Step{
					{
						Why:     "switch on the timer that installs updates",
						Command: privexec.ServiceEnableNow,
						Args:    map[string]string{"unit": "dnf-automatic.timer"},
					},
				},
				Verify: []Step{
					{
						Why:     "check the timer is on and will start at boot",
						Command: privexec.ServiceIsEnabled,
						Args:    map[string]string{"unit": "dnf-automatic.timer"},
					},
				},
				Undo: []Step{
					{
						Why:     "switch the timer off again",
						Command: privexec.ServiceDisableNow,
						Args:    map[string]string{"unit": "dnf-automatic.timer"},
					},
				},
			},
		},
	}
}

// hardenSSHConfig corrects one weak SSH setting.
//
// Same risk as the firewall, from the other direction: a bad sshd_config leaves a
// server nobody can log into. So the config is checked before the service is asked
// to read it, the service is reloaded rather than restarted, and the running
// server is asked whether the setting actually took.
func hardenSSHConfig() Action {
	return Action{
		Type:    "harden_ssh_config",
		Summary: "Set {setting} to {value} in the SSH server's configuration.",
		Params: []Param{
			{
				Name:  "setting",
				Why:   "which SSH setting to correct, from ghostpsy's own list",
				Allow: regexp.MustCompile(`^ssh\.[a-z_]+$`),
			},
			{
				Name:  "value",
				Why:   "the value to set, which each setting narrows further",
				Allow: regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`),
			},
		},
		Reversibility: ReverseFull,
		UndoWhy: "sshd_config is put back byte for byte from the copy taken before it was " +
			"edited, and the SSH server is asked to read it again.",
		Variants: []Variant{
			sshVariant("/etc/debian_version", "ssh"),
			sshVariant("/etc/redhat-release", "sshd"),
		},
	}
}

// sshVariant builds the SSH action for one family, which differ only in what the
// service is called: ssh on Debian and Ubuntu, sshd on the RHEL family.
//
// A machine that is neither gets an honest refusal rather than a reload of a
// service that does not exist.
func sshVariant(needs, unit string) Variant {
	return Variant{
		Needs:  needs,
		Backup: BackupPlan{Kind: BackupCopyFiles, Target: "/etc/ssh/sshd_config"},
		DryRun: []Step{
			{
				Why:     "show the exact line that would change",
				Command: privexec.ConfigPreview,
				Args:    map[string]string{"key": "{setting}", "value": "{value}"},
			},
		},
		Run: []Step{
			{
				Why:     "change the setting, after copying the file aside",
				Command: privexec.ConfigApply,
				Args:    map[string]string{"key": "{setting}", "value": "{value}"},
			},
			{
				// Before the reload, never after. A configuration sshd refuses is
				// caught here, while the running server is still the old one.
				Why:     "check the SSH server will accept the new configuration",
				Command: privexec.SSHTestConfig,
			},
			{
				Why:     "ask the SSH server to read it, without dropping anybody's session",
				Command: privexec.ServiceReload,
				Args:    map[string]string{"unit": unit},
			},
		},
		Verify: []Step{
			{
				Why:     "ask the running SSH server whether the setting really took",
				Command: privexec.ConfigVerify,
				Args:    map[string]string{"key": "{setting}", "value": "{value}"},
			},
			{
				Why:     "check the SSH server is still running",
				Command: privexec.ServiceIsActive,
				Args:    map[string]string{"unit": unit},
			},
			{
				Why:   "check this machine is still answering on the port you use",
				Check: CheckKeepsMeReachable,
			},
		},
		Undo: []Step{
			{
				Why:     "put sshd_config back",
				Command: privexec.ConfigRestore,
				Args:    map[string]string{"key": "{setting}"},
			},
			{
				Why:     "ask the SSH server to read the old file again",
				Command: privexec.ServiceReload,
				Args:    map[string]string{"unit": unit},
			},
		},
	}
}

// serviceSettle is how long a restarted service gets before we believe it.
//
// A service that started a second ago has proved nothing: the ones worth
// restarting are the ones that come up, fail on their config or their database,
// and go down again. Thirty seconds catches that.
const serviceSettle = 30 * time.Second

// restartFailedService starts a service that should be running and is not.
func restartFailedService() Action {
	return Action{
		Type:    "restart_failed_service",
		Summary: "Restart {unit}, which should be running and is not.",
		Params: []Param{{
			Name:  "unit",
			Why:   "the name of the service to restart",
			Allow: regexp.MustCompile(`^[A-Za-z0-9@:._-]{1,64}$`),
		}},
		Reversibility: ReverseFull,
		UndoWhy: "The service is stopped again, which is the state this machine was in " +
			"before — it was not running.",
		Settle: serviceSettle,
		Variants: []Variant{{
			DryRun: []Step{
				{
					Why:     "show the service's state and its last log lines, so you can see why it stopped",
					Command: privexec.ServiceStatus,
					Args:    map[string]string{"unit": "{unit}"},
				},
			},
			Run: []Step{
				{
					// First, so a service the owner protected is never touched at
					// all — not even for a moment.
					Why:   "check the machine's owner has not marked this service as hands off",
					Check: CheckUnitNotProtected,
				},
				{
					Why:     "restart the service",
					Command: privexec.ServiceRestart,
					Args:    map[string]string{"unit": "{unit}"},
				},
			},
			Verify: []Step{
				{
					Why:     "check the service is still running after it has had time to settle",
					Command: privexec.ServiceIsActive,
					Args:    map[string]string{"unit": "{unit}"},
				},
			},
			Undo: []Step{
				{
					Why:     "stop the service again",
					Command: privexec.ServiceStop,
					Args:    map[string]string{"unit": "{unit}"},
				},
			},
		}},
	}
}
