//go:build linux

package core

// sysctlSecurityAllowlist is a bounded set of dotted keys commonly audited (CIS/STIG style).
var sysctlSecurityAllowlist = []string{
	"kernel.kptr_restrict",
	"kernel.dmesg_restrict",
	"kernel.yama.ptrace_scope",
	"kernel.unprivileged_bpf_disabled",
	"kernel.sysrq",
	"kernel.randomize_va_space",
	"fs.protected_hardlinks",
	"fs.protected_symlinks",
	"fs.suid_dumpable",
	"net.ipv4.ip_forward",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.default.accept_source_route",
	"net.ipv4.conf.all.log_martians",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.icmp_ignore_bogus_error_responses",
	"net.ipv4.tcp_syncookies",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.all.accept_source_route",
	"dev.tty.ldisc_autoload",
}
