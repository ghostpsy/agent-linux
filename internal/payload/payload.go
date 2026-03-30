// Package payload defines the v1 ingest envelope (mirrors ingest.v1.schema.json at repo root).
package payload

import "time"

// V1 is the only supported ingest shape for schema_version == 1.
type V1 struct {
	SchemaVersion    int               `json:"schema_version"`
	MachineUUID      string            `json:"machine_uuid"`
	ScanSeq          int               `json:"scan_seq"`
	OS               OSInfo            `json:"os"`
	Listeners        []Listener        `json:"listeners"`
	Iptables         IptablesBlock     `json:"iptables"`
	HostTime         *HostTime         `json:"host_time"`
	HostSSH          *HostSSH          `json:"host_ssh,omitempty"`
	HostDisk         *HostDisk         `json:"host_disk,omitempty"`
	HostUsersSummary *HostUsersSummary `json:"host_users_summary,omitempty"`
	HostNetwork      *HostNetwork      `json:"host_network,omitempty"`
	PackagesUpdates  *PackagesUpdates  `json:"packages_updates,omitempty"`
	Firewall         *Firewall         `json:"firewall,omitempty"`
	Services         ServicesBlock     `json:"services"`
	AuditSections   []AuditSection   `json:"audit_sections,omitempty"`
}

type IptablesBlock struct {
	Items []string `json:"items"`
	// Error is set when iptables-save could not be collected.
	Error string `json:"error,omitempty"`
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

type Listener struct {
	Port         int    `json:"port"`
	Bind         string `json:"bind"`
	Process      string `json:"process"`
	BindScope    string `json:"bind_scope,omitempty"`
	ExposureRisk string `json:"exposure_risk,omitempty"`
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
	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	KexAlgorithmsSample    string   `json:"kex_algorithms_sample,omitempty"`
	CiphersSample          string   `json:"ciphers_sample,omitempty"`
	ListenAddresses        []string `json:"listen_addresses,omitempty"`
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
	PendingUpdatesCount        int    `json:"pending_updates_count,omitempty"`
	SecurityUpdatesCount       int    `json:"security_updates_count,omitempty"`
	// SecurityUpdatesSample is a capped list of package names that have security updates only.
	SecurityUpdatesSample []string `json:"security_updates_sample,omitempty"`
	// Error is set when no package manager could be used or output could not be collected.
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
