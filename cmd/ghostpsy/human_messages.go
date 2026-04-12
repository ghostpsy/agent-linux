//go:build linux

package main

import "fmt"

func humanMessageForCollectionAction(action string) string {
	switch action {
	case "collect_host_network":
		return "Extracting network interfaces and public IP candidates from local network stack"
	case "collect_host_disk":
		return "Extracting mount points and disk usage from local filesystem metadata"
	case "collect_host_users_summary":
		return "Extracting user names, shell, UID and GID from /etc/passwd"
	case "collect_host_ssh":
		return "Extracting OpenSSH hardening settings from sshd configuration files"
	case "collect_shadow_account_summary":
		return "Summarizing account lock and password hints from shadow metadata (no secrets)"
	case "collect_duplicate_uid_gid":
		return "Detecting duplicate UID and GID entries in passwd and group files"
	case "collect_password_policy_fingerprint":
		return "Reading pwquality.conf and PAM password stack lines (no secrets)"
	case "collect_sudoers_audit":
		return "Scanning sudoers structure for risky patterns (no full rule dump)"
	case "collect_packages_updates":
		return "Extracting available package updates from the system package manager"
	case "collect_host_backup":
		return "Extracting backup schedule and status from local backup configuration"
	case "collect_web_db_servers_fingerprint":
		return "Reading bounded nginx, Apache, MySQL, and PostgreSQL configuration hints"
	case "collect_redis_exposure_fingerprint":
		return "Reading redis.conf exposure flags and redis unit state (no secrets)"
	case "collect_cron_timers_inventory":
		return "Summarizing system cron, user crontabs, and systemd timers"
	case "collect_cups_exposure_fingerprint":
		return "Reading CUPS unit state and bounded cupsd Listen/WebInterface lines"
	case "collect_mta_fingerprint":
		return "Fingerprinting Postfix, Exim, or Sendmail with bounded relay hints"
	case "collect_apache_httpd_posture":
		return "Collecting Apache httpd security posture (version, listeners, modules, TLS, headers, config walk) via allowlisted commands"
	case "collect_nginx_posture":
		return "Collecting nginx metadata (version, modules sample, listen bindings, hardening hints) via allowlisted commands"
	case "collect_postfix_posture":
		return "Collecting Postfix metadata (allowlisted postconf parameters for relay and identity hints)"
	case "collect_mysql_posture":
		return "Collecting MySQL/MariaDB server metadata (version and bounded configuration hints only)"
	case "collect_postgres_posture":
		return "Collecting PostgreSQL server metadata (version, listen hints, aggregated pg_hba counts only)"
	case "collect_services":
		return "Extracting enabled/active service states from systemd and init services"
	case "collect_os_info":
		return "Extracting operating system name, version and kernel information"
	case "collect_firewall":
		return "Extracting firewall rules and default policies from nftables/iptables"
	case "collect_host_path":
		return "Extracting PATH directory entries and world-writable flags"
	case "collect_host_suid":
		return "Extracting a capped setuid binary inventory from standard locations"
	case "collect_mount_options_audit":
		return "Comparing fstab and live mount options for nodev, nosuid, and noexec on key paths"
	case "collect_path_permissions_audit":
		return "Sampling world-writable directories, /tmp sticky bit, setgid files, and unowned paths"
	case "collect_usb_storage_posture":
		return "Checking usb_storage module load state and modprobe blacklist fragments"
	case "collect_file_integrity_tooling":
		return "Detecting AIDE or Tripwire installation hints (no integrity database upload)"
	case "collect_crypt_storage_hint":
		return "Summarizing crypttab and encrypted block devices from lsblk (no keys)"
	case "collect_nfs_exports_fingerprint":
		return "Fingerprinting NFS exports with hashed paths (no raw export paths)"
	case "collect_tcp_wrappers_fingerprint":
		return "Summarizing hosts.allow and hosts.deny (bounded lines)"
	case "collect_legacy_insecure_services":
		return "Checking systemd for legacy telnet/rsh/FTP unit hints and inetd.conf"
	case "collect_host_process":
		return "Extracting top CPU and memory processes plus interpreter counts"
	case "collect_host_runtimes":
		return "Detecting language runtimes plus Docker and kubelet posture hints when present"
	case "collect_listeners":
		return "Extracting listening ports and processes from local socket tables"
	case "collect_cryptography":
		return "Scanning known TLS certificate paths for NotAfter and SHA-1 signature hints (no private keys)"
	case "collect_logging_and_system_auditing":
		return "Summarizing syslog forwarding, auditd, logrotate, at/batch, and process-accounting hints"
	default:
		return "Extracting allowlisted local system data"
	}
}

func humanDoneMessage(action string, items int) string {
	switch action {
	case "collect_host_users_summary":
		return fmt.Sprintf("Done: extracted %d user entries from /etc/passwd.", items)
	case "collect_host_disk":
		return fmt.Sprintf("Done: extracted %d filesystem usage entries.", items)
	case "collect_host_network":
		return fmt.Sprintf("Done: extracted %d network interface entries.", items)
	case "collect_services":
		return fmt.Sprintf("Done: extracted %d service entries.", items)
	case "collect_packages_updates":
		return fmt.Sprintf("Done: found %d pending package updates.", items)
	case "collect_web_db_servers_fingerprint":
		return fmt.Sprintf("Done: collected %d web/DB config signal groups.", items)
	case "collect_redis_exposure_fingerprint":
		if items == 0 {
			return "Done: no redis exposure signals collected."
		}
		return "Done: collected redis exposure signals."
	case "collect_cron_timers_inventory":
		return fmt.Sprintf("Done: summarized cron/timer inventory (%d combined signals).", items)
	case "collect_cups_exposure_fingerprint":
		if items == 0 {
			return "Done: no CUPS exposure signals collected."
		}
		return "Done: collected CUPS exposure signals."
	case "collect_mta_fingerprint":
		if items == 0 {
			return "Done: no MTA fingerprint collected."
		}
		return "Done: collected MTA fingerprint."
	case "collect_apache_httpd_posture":
		if items == 0 {
			return "Done: no Apache httpd binary detected."
		}
		return "Done: collected Apache httpd posture."
	case "collect_nginx_posture":
		if items == 0 {
			return "Done: no nginx binary detected."
		}
		return "Done: collected nginx posture."
	case "collect_postfix_posture":
		if items == 0 {
			return "Done: no Postfix binary detected."
		}
		return "Done: collected Postfix posture."
	case "collect_mysql_posture":
		if items == 0 {
			return "Done: no MySQL/MariaDB server binary detected."
		}
		return "Done: collected MySQL/MariaDB posture."
	case "collect_postgres_posture":
		if items == 0 {
			return "Done: no PostgreSQL server binary detected."
		}
		return "Done: collected PostgreSQL posture."
	case "collect_host_ssh":
		return fmt.Sprintf("Done: extracted %d SSH listen address entries.", items)
	case "collect_shadow_account_summary":
		if items == 0 {
			return "Done: shadow summary unavailable for this host."
		}
		return "Done: summarized shadow account lock and expiry hints."
	case "collect_duplicate_uid_gid":
		return fmt.Sprintf("Done: found %d duplicate UID/GID groups.", items)
	case "collect_password_policy_fingerprint":
		return fmt.Sprintf("Done: collected %d password policy signal lines.", items)
	case "collect_sudoers_audit":
		return fmt.Sprintf("Done: scanned %d sudoers files.", items)
	case "collect_listeners":
		return fmt.Sprintf("Done: extracted %d listening port entries.", items)
	case "collect_firewall":
		return fmt.Sprintf("Done: extracted %d firewall rule metrics.", items)
	case "collect_host_path":
		return fmt.Sprintf("Done: extracted %d PATH directory entries.", items)
	case "collect_host_suid":
		return fmt.Sprintf("Done: extracted %d setuid file entries.", items)
	case "collect_mount_options_audit":
		return fmt.Sprintf("Done: audited mount options for %d standard paths.", items)
	case "collect_path_permissions_audit":
		return fmt.Sprintf("Done: collected %d path permission signals.", items)
	case "collect_usb_storage_posture":
		return fmt.Sprintf("Done: recorded %d modprobe lines mentioning USB storage.", items)
	case "collect_file_integrity_tooling":
		return fmt.Sprintf("Done: collected %d FIM tooling signals.", items)
	case "collect_crypt_storage_hint":
		return fmt.Sprintf("Done: collected %d crypt volume hints.", items)
	case "collect_nfs_exports_fingerprint":
		return fmt.Sprintf("Done: fingerprinted %d NFS export lines.", items)
	case "collect_tcp_wrappers_fingerprint":
		return fmt.Sprintf("Done: summarized %d TCP wrappers rule lines.", items)
	case "collect_legacy_insecure_services":
		return fmt.Sprintf("Done: collected %d legacy insecure service signals.", items)
	case "collect_host_process":
		return fmt.Sprintf("Done: extracted %d top process entries.", items)
	case "collect_host_runtimes":
		return fmt.Sprintf("Done: detected %d language runtimes (Docker/kubelet hints when applicable).", items)
	case "collect_logging_and_system_auditing":
		return fmt.Sprintf("Done: collected %d logging and auditing signal groups.", items)
	case "collect_cryptography":
		if items == 0 {
			return "Done: no TLS certificate inventory signals collected."
		}
		return fmt.Sprintf("Done: collected %d TLS certificate inventory signals.", items)
	case "collect_host_backup":
		if items == 0 {
			return "Done: no backup tool detected on this host."
		}
		return fmt.Sprintf("Done: detected %d backup tools.", items)
	case "collect_os_info":
		return "Done: extracted operating system and kernel information."
	default:
		return fmt.Sprintf("Done: extracted %d entries.", items)
	}
}

func humanDoneWarningMessage(action string, items int, errText string) string {
	switch action {
	case "collect_host_backup":
		return fmt.Sprintf("Done with warning: no backup evidence detected (%s).", errText)
	default:
		return fmt.Sprintf("Done with warning: extracted %d entries, but encountered an issue (%s).", items, errText)
	}
}
