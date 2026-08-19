//go:build linux

package privexec

import "regexp"

// The catalogue of privileged commands.
//
// Every entry here was confirmed by measurement, not assumed: the agent was run
// as root and as an unprivileged ghostpsy user on docker/debian-13 and the two
// payloads were diffed. See internal-doc/agent-privilege-inventory.md §9 in the
// ghostpsy/ghostpsy repository.
//
// Adding an entry grants a real privilege on a customer's server. Two rules:
//
//  1. Measure before you add. If a command works unprivileged, it does not
//     belong here — a shorter grant file is a more trustworthy one.
//     Equally: remove an entry when its last caller goes. The file claims to
//     list what we use, so a grant nothing calls makes that claim false.
//  2. Write Why in plain words. It is printed above the grant, and the person
//     reading it is a busy sysadmin deciding whether to trust us.
const (
	// Firewall — the biggest gap measured: 76% of this section is lost
	// without privilege, including every rule count and both default policies.
	FirewallIptablesSave     ID = "firewall.iptables_save"
	FirewallNftListRuleset   ID = "firewall.nft_list_ruleset"
	FirewallUfwStatusVerbose ID = "firewall.ufw_status_verbose"

	// systemd — measured: these three lose data as an unprivileged user.
	SystemdDefaultTarget ID = "systemd.default_target"
	SystemdFailedUnits   ID = "systemd.failed_units"
	SystemdListTimers    ID = "systemd.list_timers"

	// Services — measured: nginx loses its whole TLS posture without this.
	NginxDumpConfig ID = "nginx.dump_config"

	// Scheduling — found by tracing, not by scanning: this one hides inside a
	// [][]string literal and no search for exec.Command would show it.
	CrontabListRoot ID = "cron.crontab_list_root"
	CrontabListSelf ID = "cron.crontab_list_self"

	// Delegated reads. A file path cannot be written as an exact sudo command,
	// so for these the agent asks its own signed binary, which enforces the
	// path allowlist internally. Keep this list very short: every entry asks
	// the reader to trust our code instead of a command they can read.
	ReadShadow  ID = "read.shadow"
	ReadSudoers ID = "read.sudoers"
	ReadGrant   ID = "read.grant"

	// ReadSSHAccess counts how many accounts could still log in over SSH. It is
	// what stops a hardening change locking the operator out of their own server.
	ReadSSHAccess ID = "read.ssh_access"

	// Everything below this line is for a fix, not a scan. They are the only
	// commands on this machine that change anything, and every one of them is
	// reachable only from a declared action in internal/action.
	//
	// Config files are written by installing a shipped file — see dropin.go. There
	// used to be four commands here that named our own binary and took the setting
	// and the value as parameters, so the grant said only "any setting, any value"
	// and the real list lived inside the binary. That is the thing this design
	// removed.

	// Services. Restarting, stopping and switching on are declared one command per
	// service in service.go, from the list of services ghostpsy actually configures —
	// `systemctl restart *` was a grant to restart anything on the machine.
	ServiceStatus    ID = "service.status"
	ServiceIsActive  ID = "service.is_active"
	ServiceIsEnabled ID = "service.is_enabled"

	// SSH. Checking the config before reloading is what stops a bad edit from
	// leaving a server nobody can log into.
	SSHTestConfig ID = "ssh.test_config"

	// Firewall, ufw — Debian and Ubuntu. `ufw --dry-run` is a real dry run: it
	// prints the exact rules it would install without installing them.
	UfwDryRunEnable    ID = "firewall.ufw_dry_run_enable"
	UfwDryRunAllowPort ID = "firewall.ufw_dry_run_allow_port"
	UfwAllowPort       ID = "firewall.ufw_allow_port"
	UfwEnable          ID = "firewall.ufw_enable"
	UfwDisable         ID = "firewall.ufw_disable"

	// Firewall, firewalld — the RHEL family. It has no dry run, so the preview
	// shows what is configured now and the run adds the port to the permanent
	// rules *before* the firewall starts.
	FirewalldState        ID = "firewall.firewalld_state"
	FirewalldListAll      ID = "firewall.firewalld_list_all"
	FirewalldAddPort      ID = "firewall.firewalld_add_port"
	FirewalldRemovePort   ID = "firewall.firewalld_remove_port"
	FirewalldReload       ID = "firewall.firewalld_reload"
	FirewalldRuntimePorts ID = "firewall.firewalld_runtime_ports"

	// Automatic security updates.
	UnattendedUpgradeDryRun ID = "updates.unattended_upgrade_dry_run"
)

// Shapes a value may take. Declared once and shared, so two commands cannot
// disagree about what a service name or a port looks like.
var (
	// A systemd unit name. No spaces, no slashes, no shell characters — and a
	// length limit, because systemd has one too.
	unitShape = regexp.MustCompile(`^[A-Za-z0-9@:._-]{1,64}$`)

	// A TCP port. 1 to 65535, and nothing that is not a number.
	portShape = regexp.MustCompile(`^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`)
)

// localeC keeps output in a language the parsers understand. sudo deletes the
// environment, so declaring it here is what makes the generator emit the
// matching env_keep line.
var localeC = []string{"LC_ALL=C", "LANG=C"}

func init() {
	declare(FirewallIptablesSave, Command{
		Binary: "iptables-save",
		Why:    "read the firewall rules, to count them and spot an open default policy",
	})
	declare(FirewallNftListRuleset, Command{
		Binary: "nft",
		Args:   []string{"list", "ruleset"},
		Why:    "read the firewall rules on hosts using nftables",
	})
	declare(FirewallUfwStatusVerbose, Command{
		Binary: "ufw",
		Args:   []string{"status", "verbose"},
		Why:    "read whether the ufw firewall is on, and its default policies",
		Env:    localeC,
	})

	declare(SystemdDefaultTarget, Command{
		Binary: "systemctl",
		Args:   []string{"get-default"},
		Why:    "read which mode this server boots into",
		Env:    localeC,
	})
	declare(SystemdFailedUnits, Command{
		Binary: "systemctl",
		Args:   []string{"--failed", "--no-legend", "--no-pager"},
		Why:    "list services that failed to start",
		Env:    localeC,
	})
	declare(SystemdListTimers, Command{
		Binary: "systemctl",
		Args:   []string{"list-timers", "--all", "--no-pager", "--output=json"},
		Why:    "list scheduled jobs, to check backups and updates actually run",
		Env:    localeC,
	})

	declare(NginxDumpConfig, Command{
		Binary: "nginx",
		Args:   []string{"-T"},
		Why:    "read the web server configuration, to check its TLS settings",
		Env:    localeC,
	})

	declare(CrontabListSelf, Command{
		Binary: "crontab",
		Args:   []string{"-l"},
		Why:    "read this account's scheduled jobs",
		Env:    localeC,
	})
	declare(CrontabListRoot, Command{
		Binary: "crontab",
		Args:   []string{"-u", "root", "-l"},
		Why:    "read root's scheduled jobs, to find backup jobs",
		Env:    localeC,
	})
	declare(ReadShadow, Command{
		Binary: agentBinaryPath,
		Args:   []string{"read-shadow"},
		Why:    "count locked and passwordless accounts. Returns only the counts — a password hash never leaves this command",
		Env:    localeC,
	})
	declare(ReadSudoers, Command{
		Binary: agentBinaryPath,
		Args:   []string{"read-sudoers"},
		Why:    "count risky sudo rules. Returns only the counts — no rule text leaves this command",
		Env:    localeC,
	})
	declare(ReadGrant, Command{
		Binary: agentBinaryPath,
		Args:   []string{"read-grant"},
		Why:    "read this very file, to report whether it is still the one this agent version needs",
		Env:    localeC,
	})

	declare(ReadSSHAccess, Command{
		Binary: agentBinaryPath,
		Args:   []string{"read-ssh-access"},
		Why: "count how many accounts could still log in over SSH, before turning one of " +
			"those ways off. Returns only the counts — no key and no file name leaves this command",
		Env: localeC,
	})

	declareFixCommands()
}

// declareFixCommands declares everything an approved fix can run.
//
// Kept apart from the reads above so the two are easy to tell apart in the grant
// file and in review. Every command here changes something or checks something a
// change did, and none of them can be reached except from a declared action.
func declareFixCommands() {
	declareServiceCommands()
	declareFirewallCommands()

	declare(SSHTestConfig, Command{
		Binary: "sshd",
		Args:   []string{"-t"},
		Why: "check the SSH configuration is valid before reloading it. " +
			"This is what stops a bad edit leaving a server nobody can log in to",
		Env: localeC,
	})
	declare(UnattendedUpgradeDryRun, Command{
		Binary: "unattended-upgrade",
		Args:   []string{"--dry-run", "--verbose"},
		Why: "show which security updates would be installed automatically in future. " +
			"--dry-run installs nothing",
		Env: localeC,
	})
}

func declareServiceCommands() {
	unit := []Param{{Name: "unit", Why: "the name of one service", Allow: unitShape}}

	// These three need no privilege, so they get none. A shorter grant file is a
	// more trustworthy one, and they are declared here only so that one readable
	// list holds everything an action can run.
	declare(ServiceIsActive, Command{
		Binary: "systemctl", Args: []string{"is-active", "{unit}"},
		Why: "check whether a service is running", Params: unit, Env: localeC, Unprivileged: true,
	})
	declare(ServiceIsEnabled, Command{
		Binary: "systemctl", Args: []string{"is-enabled", "{unit}"},
		Why: "check whether a service starts at boot", Params: unit, Env: localeC, Unprivileged: true,
	})
	declare(ServiceStatus, Command{
		Binary: "systemctl", Args: []string{"status", "--no-pager", "--lines=20", "{unit}"},
		Why: "show a service's state and its last few log lines", Params: unit, Env: localeC,
		Unprivileged: true,
	})

}

func declareFirewallCommands() {
	port := []Param{{Name: "port", Why: "one TCP port number", Allow: portShape}}

	declare(UfwDryRunEnable, Command{
		Binary: "ufw", Args: []string{"--dry-run", "--force", "enable"},
		Why: "print the firewall rules that switching the firewall on would install. " +
			"--dry-run installs nothing",
		Env: localeC,
	})
	declare(UfwDryRunAllowPort, Command{
		Binary: "ufw", Args: []string{"--dry-run", "allow", "{port}/tcp"},
		Why:    "print the rule that allowing one port would add. --dry-run installs nothing",
		Params: port, Env: localeC,
	})
	declare(UfwAllowPort, Command{
		Binary: "ufw", Args: []string{"allow", "{port}/tcp"},
		Why: "allow one TCP port through the firewall. This runs before the firewall is " +
			"switched on, so the way you reach this machine is open first",
		Params: port, Env: localeC,
	})
	declare(UfwEnable, Command{
		Binary: "ufw", Args: []string{"--force", "enable"},
		Why: "switch the firewall on", Env: localeC,
	})
	declare(UfwDisable, Command{
		Binary: "ufw", Args: []string{"--force", "disable"},
		Why: "switch the firewall off again, to undo the above. This is what runs if the check " +
			"finds the machine stopped answering",
		Env: localeC,
	})

	declare(FirewalldState, Command{
		Binary: "firewall-cmd", Args: []string{"--state"},
		Why: "check whether the firewall is running", Env: localeC,
	})
	declare(FirewalldListAll, Command{
		Binary: "firewall-cmd", Args: []string{"--list-all"},
		Why: "read the firewall rules as they are now", Env: localeC,
	})
	declare(FirewalldRuntimePorts, Command{
		Binary: "firewall-cmd", Args: []string{"--list-ports"},
		Why: "read which ports the running firewall allows", Env: localeC,
	})
	declare(FirewalldAddPort, Command{
		Binary: "firewall-cmd", Args: []string{"--permanent", "--add-port={port}/tcp"},
		Why: "allow one TCP port through the firewall from now on. This runs before the " +
			"firewall starts, so the way you reach this machine is open first",
		Params: port, Env: localeC,
	})
	declare(FirewalldRemovePort, Command{
		Binary: "firewall-cmd", Args: []string{"--permanent", "--remove-port={port}/tcp"},
		Why:    "take one allowed port back out, to undo the above",
		Params: port, Env: localeC,
	})
	declare(FirewalldReload, Command{
		Binary: "firewall-cmd", Args: []string{"--reload"},
		Why: "make the firewall re-read its rules", Env: localeC,
	})
}

// agentBinaryPath is where the installer puts the agent. The grant names this
// exact path, so a copy of the binary somewhere else is not covered by it.
const agentBinaryPath = "/usr/local/bin/ghostpsy"

// declare adds a command to the catalogue. It panics on a duplicate ID: two
// commands answering to one name is a programming error, and it must surface at
// startup rather than as a silently missing privilege on a customer's server.
func declare(id ID, c Command) {
	if _, exists := registry[id]; exists {
		panic("privexec: duplicate command ID " + string(id))
	}
	if err := checkPlaceholders(id, c); err != nil {
		panic("privexec: " + err.Error())
	}
	registry[id] = c
}
