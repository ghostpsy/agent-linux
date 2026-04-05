// Package payload defines the v1 ingest envelope (mirrors backend/ingest.v1.schema.json). There is no iptables block; use listeners[].firewall_rule.
package payload

import "time"

// V1 is the only supported ingest shape for schema_version == 1.
type V1 struct {
	SchemaVersion    int               `json:"schema_version"`
	MachineUUID      string            `json:"machine_uuid"`
	ScanSeq          int               `json:"scan_seq"`
	Hostname         string            `json:"hostname,omitempty"`
	Fqdn             string            `json:"fqdn,omitempty"`
	OS               OSInfo            `json:"os"`
	Listeners        []Listener        `json:"listeners"`
	HostTime         *HostTime         `json:"host_time"`
	HostSSH          *HostSSH          `json:"host_ssh,omitempty"`
	HostDisk         *HostDisk         `json:"host_disk,omitempty"`
	HostUsersSummary *HostUsersSummary `json:"host_users_summary,omitempty"`
	HostNetwork      *HostNetwork      `json:"host_network,omitempty"`
	PackagesUpdates  *PackagesUpdates  `json:"packages_updates,omitempty"`
	HostBackup       *HostBackup       `json:"host_backup,omitempty"`
	Firewall         *Firewall         `json:"firewall,omitempty"`
	HostPath         *HostPath         `json:"host_path,omitempty"`
	HostSuid         *HostSuid         `json:"host_suid,omitempty"`
	HostProcess      *HostProcess      `json:"host_process,omitempty"`
	HostRuntimes     *HostRuntimes     `json:"host_runtimes,omitempty"`
	Services         ServicesBlock     `json:"services"`
	AuditSections    []AuditSection    `json:"audit_sections,omitempty"`
}

type ServicesBlock struct {
	Items []ServiceEntry `json:"items"`
	// Error is set when service inventory could not be collected.
	Error string `json:"error,omitempty"`
}

type OSInfo struct {
	Pretty          string `json:"pretty"`
	Kernel          string `json:"kernel"`
	KernelArch      string `json:"kernel_arch,omitempty"`
	DistroID        string `json:"distro_id,omitempty"`         // set by API from raw fields
	DistroName      string `json:"distro_name,omitempty"`       // set by API
	DistroVersionID string `json:"distro_version_id,omitempty"` // set by API
	// Raw agent / OS (API derives distro_* for EOL).
	OSReleaseID        string `json:"os_release_id,omitempty"`
	OSReleaseVersionID string `json:"os_release_version_id,omitempty"`
	OSReleaseVersion   string `json:"os_release_version,omitempty"`
	OSReleaseName      string `json:"os_release_name,omitempty"`
	Platform           string `json:"platform,omitempty"`
	PlatformFamily     string `json:"platform_family,omitempty"`
	PlatformVersion    string `json:"platform_version,omitempty"`
}

// Listener firewall_rule values: best-effort INPUT chain classification for this TCP port.
const (
	FirewallRuleFiltered   = "filtered"
	FirewallRuleUnfiltered = "unfiltered"
	FirewallRuleBlocked    = "blocked"
	FirewallRuleUnknown    = "unknown"
)

type Listener struct {
	Port         int    `json:"port"`
	Bind         string `json:"bind"`
	Process      string `json:"process"`
	BindScope    string `json:"bind_scope,omitempty"`
	ExposureRisk string `json:"exposure_risk,omitempty"`
	FirewallRule string `json:"firewall_rule,omitempty"`
	// LanFirewallRule is a best-effort INPUT classification for TCP reachability from LAN clients.
	LanFirewallRule string `json:"lan_firewall_rule,omitempty"`
	// WanFirewallRule is a best-effort INPUT classification for TCP reachability from WAN clients.
	WanFirewallRule string `json:"wan_firewall_rule,omitempty"`
}

type HostTime struct {
	UtcNow              string   `json:"utc_now"`
	RtcInSync           *bool    `json:"rtc_in_sync,omitempty"`
	NtpActive           *bool    `json:"ntp_active,omitempty"`
	TimesyncDaemon      string   `json:"timesync_daemon,omitempty"`
	OffsetMs            *float64 `json:"offset_ms,omitempty"`
	SkewVsServerSeconds *int     `json:"skew_vs_server_seconds,omitempty"` // set by API; omitted from agent
}

type HostSSH struct {
	PermitRootLogin         string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication  string   `json:"password_authentication,omitempty"`
	ChallengeResponseAuth   string   `json:"challenge_response_auth,omitempty"`
	KexAlgorithmsSample     []string `json:"kex_algorithms_sample,omitempty"`
	CiphersSample           []string `json:"ciphers_sample,omitempty"`
	ListenAddresses         []string `json:"listen_addresses,omitempty"`
	MaxAuthTriesRecommended int      `json:"max_auth_tries_recommended,omitempty"`
	// Error is set when sshd effective configuration could not be read.
	Error string `json:"error,omitempty"`
}

type HostDisk struct {
	Filesystems []FilesystemEntry `json:"filesystems,omitempty"`
	// Error is set when host disk usage could not be collected.
	Error string `json:"error,omitempty"`
}

type FilesystemEntry struct {
	Mount         string  `json:"mount"`
	Fstype        string  `json:"fstype"`
	UsedPct       int     `json:"used_pct"`
	AvailGB       float64 `json:"avail_gb"`
	InodesUsedPct *int    `json:"inodes_used_pct,omitempty"`
}

type HostUsersSummary struct {
	NHuman          int          `json:"n_human,omitempty"`
	NSystem         int          `json:"n_system,omitempty"`
	NWithLoginShell int          `json:"n_with_login_shell,omitempty"`
	NUidZero        int          `json:"n_uid_zero,omitempty"`
	Sample          []UserSample `json:"sample,omitempty"`
	// Error is set when /etc/passwd could not be read or parsed.
	Error string `json:"error,omitempty"`
}

type UserSample struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Shell string `json:"shell"`
	Home  string `json:"home"`
}

type HostNetwork struct {
	DefaultRouteVia    string         `json:"default_route_via,omitempty"`
	HasPublicIPv4      *bool          `json:"has_public_ipv4,omitempty"`
	HasPublicIPv6      *bool          `json:"has_public_ipv6,omitempty"`
	PublicIPCandidates []string       `json:"public_ip_candidates,omitempty"`
	Interfaces         []NetworkIface `json:"interfaces,omitempty"`
	// Error is set when network interfaces could not be enumerated.
	Error string `json:"error,omitempty"`
}

type NetworkIface struct {
	Name           string         `json:"name"`
	IsLoopback     *bool          `json:"is_loopback,omitempty"`
	IsDockerBridge *bool          `json:"is_docker_bridge,omitempty"`
	Addresses      []IfaceAddress `json:"addresses,omitempty"`
}

type IfaceAddress struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"`
}

type PackagesUpdates struct {
	Manager string `json:"manager,omitempty"`
	// LastPackageIndexRefreshUTC is RFC3339 UTC: best-effort time package lists were last refreshed (e.g. apt) or RPM cache metadata.
	LastPackageIndexRefreshUTC string `json:"last_package_index_refresh_utc,omitempty"`
	// Counts are always JSON-encoded (including 0) so consumers can tell "none pending" from "unknown".
	PendingUpdatesCount  int `json:"pending_updates_count"`
	SecurityUpdatesCount int `json:"security_updates_count"`
	// SecurityUpdatesSample is a capped list of package names that have security updates only.
	SecurityUpdatesSample []string `json:"security_updates_sample,omitempty"`
	// Error is set when no package manager could be used or output could not be collected.
	Error string `json:"error,omitempty"`
}

// HostBackup summarizes whether we detect backup tooling/automation on the host.
// backup_status intentionally uses "on" or "unknown" (no "off") to avoid false negatives.
type HostBackup struct {
	BackupStatus string `json:"backup_status"` // on | unknown
	// LatestBackupUTC is RFC3339 UTC when detected, otherwise "unknown".
	LatestBackupUTC string `json:"latest_backup_utc"`
	// ToolsDetected are known backup tool binaries found on the host.
	ToolsDetected []string `json:"tools_detected,omitempty"`
	// HasPeriodicCron is true when cron hints suggest periodic backups.
	HasPeriodicCron *bool `json:"has_periodic_cron,omitempty"`
	// Error is set when collection failed hard.
	Error string `json:"error,omitempty"`
}

// Firewall summarizes detected host firewall (Linux-focused).
type Firewall struct {
	Family                string `json:"firewall_family"`
	DefaultPolicyIn       string `json:"default_policy_in,omitempty"`
	DefaultPolicyOut      string `json:"default_policy_out,omitempty"`
	RuleCount             *int   `json:"rule_count,omitempty"`
	HasEstablishedRelated *bool  `json:"has_established_related,omitempty"`
	// Managers lists common userspace daemons (firewalld, ufw): CLI on PATH and runtime active state.
	Managers []FirewallManager `json:"firewall_managers"`
	// Error is set when firewall metrics could not be collected via nftables or iptables APIs.
	Error string `json:"error,omitempty"`
}

// FirewallManager is a known firewall management tool (not the netfilter backend).
type FirewallManager struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
}

// HostPath lists PATH components with existence and world-writable flags (M1).
type HostPath struct {
	Entries []PathEntry `json:"entries"`
	Error   string      `json:"error,omitempty"`
}

// PathEntry is one directory from $PATH (user-home entries are skipped).
type PathEntry struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	WorldWritable bool   `json:"world_writable"`
}

// HostSuid is a capped list of setuid binaries (M1).
type HostSuid struct {
	Items []SuidItem `json:"items"`
	Error string     `json:"error,omitempty"`
}

// SuidItem is one setuid file with owner and permission bits (octal string).
type SuidItem struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"`
}

// HostProcess is top processes plus interpreter / heuristic signals (M1).
type HostProcess struct {
	Top     []ProcessTopEntry `json:"top"`
	Signals *ProcessSignals   `json:"signals,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// ProcessTopEntry is one process snapshot for top-CPU / top-RSS merge.
type ProcessTopEntry struct {
	Pid              int32   `json:"pid"`
	Name             string  `json:"name"`
	User             string  `json:"user"`
	CpuPct           float64 `json:"cpu_pct"`
	RssMb            float64 `json:"rss_mb"`
	CmdlineTruncated string  `json:"cmdline_truncated"`
}

// ProcessSignals counts interpreter processes and heuristic “suspicious worker” hints.
type ProcessSignals struct {
	InterpreterPython  int `json:"interpreter_python,omitempty"`
	InterpreterNode    int `json:"interpreter_node,omitempty"`
	InterpreterJava    int `json:"interpreter_java,omitempty"`
	UnknownHashWorkers int `json:"unknown_hash_workers,omitempty"`
}

// HostRuntimes lists detected language runtimes (capped, M1).
type HostRuntimes struct {
	Items []RuntimeEntry `json:"items"`
	Error string         `json:"error,omitempty"`
}

// RuntimeEntry is one resolved interpreter runtime on PATH.
type RuntimeEntry struct {
	Kind       string `json:"kind"`
	Version    string `json:"version"`
	BinaryPath string `json:"binary_path"`
	ManagedBy  string `json:"managed_by"`
}

// ServiceEntry is a single unit from the init system (systemd or sysvinit on Linux).
type ServiceEntry struct {
	Name          string `json:"name"`
	Manager       string `json:"manager"`
	Enabled       *bool  `json:"enabled,omitempty"`
	ActiveState   string `json:"active_state,omitempty"`
	UnitFileState string `json:"unit_file_state,omitempty"`
}

type AuditSection struct {
	ID     string       `json:"id"`
	Title  string       `json:"title"`
	Checks []AuditCheck `json:"checks"`
}

type AuditCheck struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AgentUtcRFC3339 UTC timestamp for host_time.utc_now (agent-side).
func AgentUtcRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
