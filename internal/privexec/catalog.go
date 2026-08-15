//go:build linux

package privexec

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
//  2. Write Why in plain words. It is printed above the grant, and the person
//     reading it is a busy sysadmin deciding whether to trust us.
const (
	// Firewall — the biggest gap measured: 76% of this section is lost
	// without privilege, including every rule count and both default policies.
	FirewallIptablesSave     ID = "firewall.iptables_save"
	FirewallIptablesList     ID = "firewall.iptables_list"
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
	declare(FirewallIptablesList, Command{
		Binary: "iptables",
		Args:   []string{"-t", "filter", "-S"},
		Why:    "read the firewall filter table",
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
}

// declare adds a command to the catalogue. It panics on a duplicate ID: two
// commands answering to one name is a programming error, and it must surface at
// startup rather than as a silently missing privilege on a customer's server.
func declare(id ID, c Command) {
	if _, exists := registry[id]; exists {
		panic("privexec: duplicate command ID " + string(id))
	}
	registry[id] = c
}
