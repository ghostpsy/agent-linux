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

	// SSHDumpConfig is the effective sshd configuration, which only sshd itself
	// can work out: it is the main file, plus every drop-in, plus the built-in
	// defaults, resolved in the order sshd applies them. Reading sshd_config
	// would answer a different question and answer it wrongly — a drop-in shipped
	// by cloud-init routinely overrides what that file says.
	SSHDumpConfig ID = "ssh.dump_config"

	// Scheduling — found by tracing, not by scanning: this one hides inside a
	// [][]string literal and no search for exec.Command would show it.
	CrontabListRoot ID = "cron.crontab_list_root"
	CrontabListSelf ID = "cron.crontab_list_self"

	// Privileged reads, every one a command a reviewer already knows.
	//
	// These used to be `ghostpsy read-shadow` and friends: our own binary,
	// printing a summary. It was safe, and it was unreadable. A security team
	// auditing /etc/sudoers.d/ghostpsy could not tell what ran as root without
	// reading our source, and a team that has to read your source to approve you
	// does not approve you.
	//
	// So each one is now a standard command whose output is already safe to hand
	// over, and the counting happens afterwards, unprivileged. `passwd -S -a`
	// prints an account status per line and never a hash; that is the whole
	// argument, and it applies to all four.
	GrantFile ID = "read.grant_file"

	// ShadowAccountStatus and LastlogAll together answer what read-shadow did:
	// how many accounts are locked, how many have no password, how many have
	// never logged in. Neither prints password material of any kind.
	ShadowAccountStatus ID = "read.shadow_account_status"
	LastlogAll          ID = "read.lastlog_all"

	// SudoersText is every sudo rule on the host, with the file each came from.
	// `.` matches any non-empty line, so this is "print these files, numbered".
	SudoersText ID = "read.sudoers_text"

	// AuthorizedKeysFiles finds which accounts still have an SSH key, which is
	// what stops a hardening change locking the operator out of their own
	// server. /etc/passwd is world-readable, so the agent already knows the home
	// directories; the only thing it needs root for is whether the key file is
	// there and not empty.
	AuthorizedKeysFiles ID = "read.authorized_keys_files"

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
	// The rules ufw has been given, which is not the same as the rules it is
	// enforcing. `ufw status` shows nothing at all while the firewall is off.
	UfwShowAdded ID = "firewall.ufw_show_added"
	UfwAllowPort ID = "firewall.ufw_allow_port"
	UfwEnable    ID = "firewall.ufw_enable"
	UfwDisable   ID = "firewall.ufw_disable"

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

	// Time. The package is named in the command, not passed to it — see the
	// declarations for why that matters.
	// Whether the clock daemon is running, asked of the process table rather than
	// of systemd. `systemctl is-active` cannot answer it on a machine that has no
	// systemd, and Ubuntu 14.04 is exactly the machine this action is for.
	NTPDaemonRunning    ID = "time.ntp_daemon_running"
	ChronyDaemonRunning ID = "time.chrony_daemon_running"

	AptInstallNTP            ID = "time.apt_install_ntp"
	AptSimulateInstallNTP    ID = "time.apt_simulate_install_ntp"
	DnfInstallChrony         ID = "time.dnf_install_chrony"
	DnfSimulateInstallChrony ID = "time.dnf_simulate_install_chrony"

	// Setting the clock, as opposed to installing something that will get round
	// to it. A freshly installed ntpd needs several poll cycles before it will
	// step a badly wrong clock, so a machine can be "fixed" and still be hours
	// out — which is a fix that reports success and leaves the finding standing.
	NTPServiceStop  ID = "time.ntp_service_stop"
	NTPServiceStart ID = "time.ntp_service_start"
	NTPStepClock    ID = "time.ntp_step_clock"
	ChronyStepClock ID = "time.chrony_step_clock"
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

	declare(SSHDumpConfig, Command{
		Binary: "sshd",
		Args:   []string{"-T"},
		Why: "read the SSH server's effective settings, to report whether root may log in " +
			"and whether passwords are accepted. sshd prints them; it changes nothing",
		Env: localeC,
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
	declare(GrantFile, Command{
		Binary: "cat",
		Args:   []string{GrantPath},
		Why:    "read this very file, to report whether it is still the one this agent version needs",
		Env:    localeC,
	})

	declare(ShadowAccountStatus, Command{
		Binary: "passwd",
		Args:   []string{"-S", "-a"},
		Why: "print one status line per account — locked, no password, or usable — to count " +
			"the accounts nobody can log in to. It prints no password material of any kind",
		Env: localeC,
	})
	declare(LastlogAll, Command{
		Binary: "lastlog",
		Args:   nil,
		Why:    "print the last login time of every account, to count the ones never used",
		Env:    localeC,
	})

	declare(SudoersText, Command{
		Binary: "grep",
		Args:   []string{"-rn", ".", "/etc/sudoers", "/etc/sudoers.d/"},
		Why: "print every sudo rule on this host with the file it came from, to count the " +
			"risky ones. `.` matches any line that is not blank",
		Env: localeC,
	})

	declare(AuthorizedKeysFiles, Command{
		Binary: "find",
		Args: []string{
			"/root", "/home",
			"-maxdepth", "4",
			"-name", "authorized_keys",
			"-size", "+0",
		},
		Why: "list which accounts have an SSH key that is not empty, before turning off " +
			"another way of logging in. It prints file names, never a key",
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
	// Installing a time daemon. One literal command per distribution family, with
	// the package named in the grant — never a parameter. A rule that read
	// `apt-get install -y *` would let the agent install anything at all, which is
	// the whole thing the explicit grant exists to prevent.
	// Unprivileged, so these two never reach the sudo grant at all. Reading the
	// process table needs no privilege, and a grant that buys nothing is a line a
	// reviewer has to read for no reason.
	declare(NTPDaemonRunning, Command{
		Binary:       "pgrep",
		Args:         []string{"-x", "ntpd"},
		Why:          "check the time service is running",
		Env:          localeC,
		Unprivileged: true,
	})
	declare(ChronyDaemonRunning, Command{
		Binary:       "pgrep",
		Args:         []string{"-x", "chronyd"},
		Why:          "check the time service is running",
		Env:          localeC,
		Unprivileged: true,
	})

	declare(AptInstallNTP, Command{
		Binary:    "apt-get",
		Args:      []string{"install", "-y", "ntp"},
		Why:       "install the ntp time service, so this machine's clock stays correct",
		Env:       localeC,
		NeedsPath: "/etc/apt",
	})
	declare(AptSimulateInstallNTP, Command{
		Binary: "apt-get",
		Args:   []string{"install", "--simulate", "ntp"},
		Why: "show what installing the ntp time service would pull in. " +
			"--simulate installs nothing",
		Env:       localeC,
		NeedsPath: "/etc/apt",
	})
	declare(DnfInstallChrony, Command{
		Binary:    "dnf",
		Args:      []string{"install", "-y", "chrony"},
		Why:       "install the chrony time service, so this machine's clock stays correct",
		Env:       localeC,
		NeedsPath: "/etc/dnf",
	})
	declare(DnfSimulateInstallChrony, Command{
		Binary: "dnf",
		Args:   []string{"install", "--assumeno", "chrony"},
		Why: "show what installing the chrony time service would pull in. " +
			"--assumeno answers no, so nothing is installed",
		Env:       localeC,
		NeedsPath: "/etc/dnf",
	})

	// ntpd will not take port 123 while the daemon holds it, so the daemon is
	// stopped for the few seconds the clock is being set and started again after.
	//
	// `service` rather than `systemctl`, because this is the one action written
	// for machines that have no systemd to ask. Ubuntu 14.04 has /etc/init.d/ntp
	// and /usr/sbin/service, and `service` is what a sysadmin on any of these
	// systems would type.
	declare(NTPServiceStop, Command{
		Binary:    "service",
		Args:      []string{"ntp", "stop"},
		Why:       "stop the time service for a moment, so the clock can be set",
		Env:       localeC,
		NeedsPath: "/etc/apt",
	})
	declare(NTPServiceStart, Command{
		Binary:    "service",
		Args:      []string{"ntp", "start"},
		Why:       "start the time service again",
		Env:       localeC,
		NeedsPath: "/etc/apt",
	})

	// -q sets the clock once and exits, -g allows it to do so however far out the
	// clock is. Without -g ntpd refuses any correction beyond about 1000 seconds,
	// which is exactly the case worth fixing: a machine resumed from a snapshot
	// hours or days behind.
	declare(NTPStepClock, Command{
		Binary:    "ntpd",
		Args:      []string{"-gq"},
		Why:       "set the clock now, however far out it is, instead of waiting for the daemon to get round to it",
		Env:       localeC,
		NeedsPath: "/etc/apt",
	})

	// chrony needs no stop and start: makestep tells the daemon that is already
	// running to correct the clock in one jump now.
	declare(ChronyStepClock, Command{
		Binary:    "chronyc",
		Args:      []string{"makestep"},
		Why:       "set the clock now, instead of waiting for the daemon to get round to it",
		Env:       localeC,
		NeedsPath: "/etc/dnf",
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
	// `ufw status` is not enough to answer "will my way in still work".
	//
	// On a machine whose firewall is off — the only machine this action runs on —
	// status prints "Status: inactive" and lists no rules, while the rules are
	// sitting in the configuration waiting to be enforced. `show added` is what
	// prints those.
	declare(UfwShowAdded, Command{
		Binary: "ufw",
		Args:   []string{"show", "added"},
		Why:    "read the rules ufw already has, which it does not show while it is switched off",
		Env:    localeC,
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

// GrantPath is where the grant lives once a host has one. It is named here
// because this package writes it, and read back through GrantFile.
const GrantPath = "/etc/sudoers.d/ghostpsy"

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
