// Package payload defines the v1 ingest envelope (mirrors api/ingest.v1.schema.json).
// Facts live only under components.*; per-port firewall posture is listeners[].firewall_rule.
package payload

import "time"

// V1 is the only supported ingest shape for schema_version == 1.
type V1 struct {
	SchemaVersion int        `json:"schema_version"`
	MachineUUID   string     `json:"machine_uuid"`
	ScanSeq       int        `json:"scan_seq"`
	Hostname      string     `json:"hostname,omitempty"`
	Fqdn          string     `json:"fqdn,omitempty"`
	Components    Components `json:"components"`
}

// Components groups inventory by competitor-audited sections (RBAC boundary).
type Components struct {
	CoreSystemAndKernel                 CoreSystemAndKernelComponent                 `json:"core_system_and_kernel"`
	IdentityAccessAndAuthentication     IdentityAccessAndAuthenticationComponent     `json:"identity_access_and_authentication"`
	FileSystemAndStorage                FileSystemAndStorageComponent                `json:"file_system_and_storage"`
	NetworkAndHostFirewall              NetworkAndHostFirewallComponent              `json:"network_and_host_firewall"`
	SoftwarePackagesAndApplications     SoftwarePackagesAndApplicationsComponent     `json:"software_packages_and_applications"`
	ContainerAndCloudNativeLinux        ContainerAndCloudNativeLinuxComponent        `json:"container_and_cloud_native_linux"`
	LoggingAndSystemAuditing            LoggingAndSystemAuditingComponent            `json:"logging_and_system_auditing"`
	Cryptography                        CryptographyComponent                        `json:"cryptography"`
	SecurityFrameworksAndMalwareDefense SecurityFrameworksAndMalwareDefenseComponent `json:"security_frameworks_and_malware_defense"`
	Other                               OtherComponent                               `json:"other"`
}

type CoreSystemAndKernelComponent struct {
	OS              OSInfo                  `json:"os"`
	HostTime        *HostTime               `json:"host_time,omitempty"`
	HostProcess     *HostProcess            `json:"host_process,omitempty"`
	Grub            *GrubSnapshot           `json:"grub,omitempty"`
	FirmwareBoot    *FirmwareBoot           `json:"firmware_boot,omitempty"`
	SystemdHealth   *SystemdHealth          `json:"systemd_health,omitempty"`
	SysctlLive      *SysctlLiveBlock        `json:"sysctl_live,omitempty"`
	SysctlOverlay   *SysctlOverlayBlock     `json:"sysctl_overlay,omitempty"`
	KernelModules   *KernelModulesBlock     `json:"kernel_modules,omitempty"`
	SelinuxApparmor *SelinuxApparmorBlock   `json:"selinux_apparmor,omitempty"`
	HighRiskProcess *HighRiskProcessSurface `json:"high_risk_process,omitempty"`
}

type IdentityAccessAndAuthenticationComponent struct {
	HostUsersSummary          *HostUsersSummary          `json:"host_users_summary,omitempty"`
	HostSSH                   *HostSSH                   `json:"host_ssh,omitempty"`
	ShadowAccountSummary      *ShadowAccountSummary      `json:"shadow_account_summary,omitempty"`
	DuplicateUidGid           *DuplicateUidGid           `json:"duplicate_uid_gid,omitempty"`
	PasswordPolicyFingerprint *PasswordPolicyFingerprint `json:"password_policy_fingerprint,omitempty"`
	SudoersAudit              *SudoersAudit              `json:"sudoers_audit,omitempty"`
}

type FileSystemAndStorageComponent struct {
	HostDisk              *HostDisk              `json:"host_disk,omitempty"`
	HostPath              *HostPath              `json:"host_path,omitempty"`
	HostSuid              *HostSuid              `json:"host_suid,omitempty"`
	MountOptionsAudit     *MountOptionsAudit     `json:"mount_options_audit,omitempty"`
	PathPermissionsAudit  *PathPermissionsAudit  `json:"path_permissions_audit,omitempty"`
	UsbStoragePosture     *UsbStoragePosture     `json:"usb_storage_posture,omitempty"`
	FileIntegrityTooling  *FileIntegrityTooling  `json:"file_integrity_tooling,omitempty"`
	CryptStorageHint      *CryptStorageHint      `json:"crypt_storage_hint,omitempty"`
	NfsExportsFingerprint *NfsExportsFingerprint `json:"nfs_exports_fingerprint,omitempty"`
}

type NetworkAndHostFirewallComponent struct {
	Listeners              []Listener              `json:"listeners"`
	HostNetwork            *HostNetwork            `json:"host_network,omitempty"`
	Firewall               *Firewall               `json:"firewall,omitempty"`
	TcpWrappersFingerprint *TcpWrappersFingerprint `json:"tcp_wrappers_fingerprint,omitempty"`
	LegacyInsecureServices *LegacyInsecureServices `json:"legacy_insecure_services,omitempty"`
}

type SoftwarePackagesAndApplicationsComponent struct {
	Services                 ServicesBlock             `json:"services"`
	PackagesUpdates          *PackagesUpdates          `json:"packages_updates,omitempty"`
	HostBackup               *HostBackup               `json:"host_backup,omitempty"`
	HostRuntimes             *HostRuntimes             `json:"host_runtimes,omitempty"`
	WebDbServersFingerprint  *WebDbServersFingerprint  `json:"web_db_servers_fingerprint,omitempty"`
	RedisExposureFingerprint *RedisExposureFingerprint `json:"redis_exposure_fingerprint,omitempty"`
	CronTimersInventory      *CronTimersInventory      `json:"cron_timers_inventory,omitempty"`
	CupsExposureFingerprint  *CupsExposureFingerprint  `json:"cups_exposure_fingerprint,omitempty"`
	MtaFingerprint           *MtaFingerprint           `json:"mta_fingerprint,omitempty"`
	ApacheHttpdPosture       *ApacheHttpdPosture       `json:"apache_httpd_posture,omitempty"`
	NginxPosture             *NginxPosture             `json:"nginx_posture,omitempty"`
	PostfixPosture           *PostfixPosture           `json:"postfix_posture,omitempty"`
	MysqlPosture             *MysqlPosture             `json:"mysql_posture,omitempty"`
	PostgresPosture          *PostgresPosture          `json:"postgres_posture,omitempty"`
	DockerPosture            *DockerPosture            `json:"docker_posture,omitempty"`
}

type ContainerAndCloudNativeLinuxComponent struct {
	HostRuntimes      *ContainerNativeHostRuntimes `json:"host_runtimes,omitempty"`
	ContainerWorkloads *ContainerWorkloads         `json:"container_workloads,omitempty"`
}

// ContainerWorkloads is a bounded inventory of running Docker containers and
// Kubernetes pods on the host. Distinct from DockerPosture (security posture)
// and ContainerNativeHostRuntimes (daemon/kubelet fingerprints): this block
// surfaces what workloads are actually running so the report can talk about
// them as business assets (like apps in #134).
type ContainerWorkloads struct {
	// DockerContainers is the list of running Docker containers, capped.
	DockerContainers []DockerContainerWorkload `json:"docker_containers"`
	// DockerContainersTruncated is true when the host had more running
	// containers than the collector's cap.
	DockerContainersTruncated bool `json:"docker_containers_truncated"`
	// KubeletPods is the list of pods observed on this node via the
	// kubelet read-only port or crictl, capped. Empty when neither signal
	// is available.
	KubeletPods []KubeletPodWorkload `json:"kubelet_pods"`
	// KubeletPodsTruncated is true when the node had more pods than the cap.
	KubeletPodsTruncated bool `json:"kubelet_pods_truncated"`
	// CollectorWarnings surfaces transient issues (CLI missing, parse errors).
	CollectorWarnings []string `json:"collector_warnings,omitempty"`
}

// DockerContainerWorkload describes one running Docker container, workload-first.
// No env vars, no command-line flags (may carry secrets) — only image identity,
// runtime state, and whitelisted labels.
type DockerContainerWorkload struct {
	Name           string   `json:"name"`
	ContainerID    string   `json:"container_id"`
	Image          string   `json:"image"`
	ImageTag       string   `json:"image_tag,omitempty"`
	ImageDigest    string   `json:"image_digest,omitempty"`
	ImageTagLatest bool     `json:"image_tag_is_latest"`
	ImageDigestPinned bool  `json:"image_digest_pinned"`
	State          string   `json:"state"`
	StartedAt      string   `json:"started_at,omitempty"`
	RestartCount   int      `json:"restart_count"`
	User           string   `json:"user,omitempty"`
	EntrypointHint string   `json:"entrypoint_hint,omitempty"`
	WorkloadHint   string   `json:"workload_hint,omitempty"`
	NetworkMode    string   `json:"network_mode,omitempty"`
	// WorkloadLabels carries only allow-listed compose/kubernetes/OCI labels
	// that identify the workload to the operator. Never arbitrary user labels.
	WorkloadLabels map[string]string `json:"workload_labels,omitempty"`
}

// KubeletPodWorkload describes one pod observed via kubelet / crictl on this node.
type KubeletPodWorkload struct {
	Name        string                        `json:"name"`
	Namespace   string                        `json:"namespace"`
	Phase       string                        `json:"phase,omitempty"`
	CreatedAt   string                        `json:"created_at,omitempty"`
	Containers  []KubeletContainerWorkload    `json:"containers"`
}

// KubeletContainerWorkload is a single container inside a pod.
type KubeletContainerWorkload struct {
	Name              string `json:"name"`
	Image             string `json:"image"`
	ImageTag          string `json:"image_tag,omitempty"`
	ImageDigest       string `json:"image_digest,omitempty"`
	ImageTagLatest    bool   `json:"image_tag_is_latest"`
	ImageDigestPinned bool   `json:"image_digest_pinned"`
	RestartCount      int    `json:"restart_count"`
	State             string `json:"state,omitempty"`
}

// ContainerNativeHostRuntimes is §6 host_runtimes: Docker daemon and kubelet hints only (no language runtime items).
type ContainerNativeHostRuntimes struct {
	Docker  *DockerHostFingerprint  `json:"docker,omitempty"`
	Kubelet *KubeletNodeFingerprint `json:"kubelet,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

type LoggingAndSystemAuditingComponent struct {
	AuditSections     []AuditSection            `json:"audit_sections,omitempty"`
	SyslogForwarding  *SyslogForwardingPosture  `json:"syslog_forwarding,omitempty"`
	Journald          *JournaldPosture          `json:"journald,omitempty"`
	Auditd            *AuditdPosture            `json:"auditd,omitempty"`
	LogrotateDisk     *LogrotateDiskPosture     `json:"logrotate_disk,omitempty"`
	AtBatch           *AtBatchPosture           `json:"at_batch,omitempty"`
	ProcessAccounting *ProcessAccountingPosture `json:"process_accounting,omitempty"`
}

// CryptographyComponent holds TLS/cert inventory; clock baseline lives under core_system_and_kernel.host_time.
type CryptographyComponent struct {
	LocalTlsCertInventory *LocalTlsCertInventory `json:"local_tls_cert_inventory,omitempty"`
}

// LocalTlsCertInventory is a bounded scan of PEM leaf material from known paths (NotAfter and signature algorithm hints only).
type LocalTlsCertInventory struct {
	Items                  []LocalTlsCertFileEntry `json:"items,omitempty"`
	Sha1SignatureCertCount int                     `json:"sha1_signature_cert_count,omitempty"`
	FilesScanned           int                     `json:"files_scanned,omitempty"`
	Error                  string                  `json:"error,omitempty"`
}

// LocalTlsCertFileEntry describes one certificate (first PEM block per file, typically the leaf).
type LocalTlsCertFileEntry struct {
	Path                string `json:"path"`
	NotAfter            string `json:"not_after"`
	ExpiresWithin30Days *bool  `json:"expires_within_30_days,omitempty"`
	UsesSha1Signature   *bool  `json:"uses_sha1_signature,omitempty"`
}

// OtherComponent is reserved; send {} until extensions are defined.
type OtherComponent struct{}

type ServicesBlock struct {
	Items []ServiceEntry `json:"items"`
	Error string         `json:"error,omitempty"`
}

type OSInfo struct {
	Pretty          string `json:"pretty"`
	Kernel          string `json:"kernel"`
	KernelArch      string `json:"kernel_arch,omitempty"`
	DistroID        string `json:"distro_id,omitempty"`
	DistroName      string `json:"distro_name,omitempty"`
	DistroVersionID string `json:"distro_version_id,omitempty"`
	// True when agent detects Ubuntu Pro ESM or Debian ELTS-style apt; API uses this for ESM/ELTS posture.
	DistroPaidExtendedSecurityActive *bool  `json:"distro_paid_extended_security_active,omitempty"`
	OSReleaseID                      string `json:"os_release_id,omitempty"`
	OSReleaseVersionID               string `json:"os_release_version_id,omitempty"`
	OSReleaseVersion                 string `json:"os_release_version,omitempty"`
	OSReleaseName                    string `json:"os_release_name,omitempty"`
	Platform                         string `json:"platform,omitempty"`
	PlatformFamily                   string `json:"platform_family,omitempty"`
	PlatformVersion                  string `json:"platform_version,omitempty"`
}

const (
	FirewallRuleFiltered   = "filtered"
	FirewallRuleUnfiltered = "unfiltered"
	FirewallRuleBlocked    = "blocked"
	FirewallRuleUnknown    = "unknown"
)

type Listener struct {
	Port               int    `json:"port"`
	Bind               string `json:"bind"`
	Process            string `json:"process"`
	ListenPid          int32  `json:"listen_pid,omitempty"`
	SystemdUnit        string `json:"systemd_unit,omitempty"`
	SystemdUnitMissing bool   `json:"systemd_unit_missing,omitempty"`
	BindScope          string `json:"bind_scope,omitempty"`
	ExposureRisk       string `json:"exposure_risk,omitempty"`
	FirewallRule       string `json:"firewall_rule,omitempty"`
	LanFirewallRule    string `json:"lan_firewall_rule,omitempty"`
	WanFirewallRule    string `json:"wan_firewall_rule,omitempty"`
	WanProbeOpen       *bool  `json:"wan_probe_open,omitempty"`
}

type HostTime struct {
	UtcNow              string   `json:"utc_now"`
	RtcInSync           *bool    `json:"rtc_in_sync,omitempty"`
	NtpActive           *bool    `json:"ntp_active,omitempty"`
	TimesyncDaemon      string   `json:"timesync_daemon,omitempty"`
	OffsetMs            *float64 `json:"offset_ms,omitempty"`
	SkewVsServerSeconds *int     `json:"skew_vs_server_seconds,omitempty"`
}

type HostSSH struct {
	PermitRootLogin            string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication     string   `json:"password_authentication,omitempty"`
	ChallengeResponseAuth      string   `json:"challenge_response_auth,omitempty"`
	KexAlgorithmsSample        []string `json:"kex_algorithms_sample,omitempty"`
	CiphersSample              []string `json:"ciphers_sample,omitempty"`
	ListenAddresses            []string `json:"listen_addresses,omitempty"`
	MaxAuthTries               *int     `json:"max_auth_tries,omitempty"`
	ClientAliveIntervalSeconds *int     `json:"client_alive_interval_seconds,omitempty"`
	ClientAliveCountMax        *int     `json:"client_alive_count_max,omitempty"`
	AllowUsersPresent          *bool    `json:"allow_users_present,omitempty"`
	DenyUsersPresent           *bool    `json:"deny_users_present,omitempty"`
	Subsystem                  string   `json:"subsystem,omitempty"`
	UsePAM                     string   `json:"use_pam,omitempty"`
	X11Forwarding              string   `json:"x11_forwarding,omitempty"`
	Error                      string   `json:"error,omitempty"`
}

type HostDisk struct {
	Filesystems []FilesystemEntry `json:"filesystems,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type FilesystemEntry struct {
	Mount         string `json:"mount"`
	Fstype        string `json:"fstype"`
	UsedPct       int    `json:"used_pct"`
	AvailGB       int    `json:"avail_gb"`
	InodesUsedPct *int   `json:"inodes_used_pct,omitempty"`
}

type HostUsersSummary struct {
	NHuman          int          `json:"n_human,omitempty"`
	NSystem         int          `json:"n_system,omitempty"`
	NWithLoginShell int          `json:"n_with_login_shell,omitempty"`
	NUidZero        int          `json:"n_uid_zero,omitempty"`
	Sample          []UserSample `json:"sample,omitempty"`
	Error           string       `json:"error,omitempty"`
}

// UserSample is intentionally free of login names and home paths (PII); uid/gid/shell only.
type UserSample struct {
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Shell string `json:"shell"`
}

type HostNetwork struct {
	DefaultRouteVia         string         `json:"default_route_via,omitempty"`
	HasPublicIPv4           *bool          `json:"has_public_ipv4,omitempty"`
	HasPublicIPv6           *bool          `json:"has_public_ipv6,omitempty"`
	PublicIPCandidates      []string       `json:"public_ip_candidates,omitempty"` // redacted: IPv4 a.b.x.x / IPv6 h:h:x:x:x:x:x:x
	ProbeTargets            []string       `json:"probe_targets,omitempty"`         // real public IPs for API-side WAN probing
	Interfaces              []NetworkIface `json:"interfaces,omitempty"`
	ResolvConfNameservers   []string       `json:"resolv_conf_nameservers,omitempty"`
	ResolvConfSearchDomains []string       `json:"resolv_conf_search_domains,omitempty"`
	ResolvConfSampleLines   []string       `json:"resolv_conf_sample_lines,omitempty"`
	SystemdResolvedStub     *bool          `json:"systemd_resolved_stub,omitempty"`
	Error                   string         `json:"error,omitempty"`
}

type NetworkIface struct {
	Name           string         `json:"name"`
	Type           string         `json:"type"`
	IsDockerBridge *bool          `json:"is_docker_bridge,omitempty"`
	Ipv6Enabled    *bool          `json:"ipv6_enabled,omitempty"`
	Promiscuous    *bool          `json:"promiscuous,omitempty"`
	Addresses      []IfaceAddress `json:"addresses,omitempty"`
}

type IfaceAddress struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"`
}

type PackagesUpdates struct {
	Manager                    string   `json:"manager,omitempty"`
	LastPackageIndexRefreshUTC string   `json:"last_package_index_refresh_utc,omitempty"`
	InstalledPackageCount      int      `json:"installed_package_count"`
	PendingUpdatesCount        int      `json:"pending_updates_count"`
	SecurityUpdatesCount       int      `json:"security_updates_count"`
	SecurityUpdatesSample      []string `json:"security_updates_sample,omitempty"`
	Error                      string   `json:"error,omitempty"`
}

type HostBackup struct {
	BackupStatus    string   `json:"backup_status"`
	LatestBackupUTC string   `json:"latest_backup_utc"`
	ToolsDetected   []string `json:"tools_detected,omitempty"`
	HasPeriodicCron *bool    `json:"has_periodic_cron,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type Firewall struct {
	Family                  string   `json:"firewall_family"`
	Active                  bool     `json:"active"`
	DefaultPolicyIn         string   `json:"default_policy_in,omitempty"`
	DefaultPolicyOut        string   `json:"default_policy_out,omitempty"`
	RuleCount               *int     `json:"rule_count,omitempty"`
	HasEstablishedRelated   *bool    `json:"has_established_related,omitempty"`
	FirewalldDefaultZone    string   `json:"firewalld_default_zone,omitempty"`
	FirewalldZoneTarget     string   `json:"firewalld_zone_target,omitempty"`
	UfwStatusVerboseSample  []string `json:"ufw_status_verbose_sample,omitempty"`
	BackendRulesetSha256Hex string   `json:"backend_ruleset_sha256,omitempty"`
	BackendRulesetExcerpt   string   `json:"backend_ruleset_excerpt,omitempty"`
	Error                   string   `json:"error,omitempty"`
}

type HostPath struct {
	Entries []PathEntry `json:"entries"`
	Error   string      `json:"error,omitempty"`
}

type PathEntry struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	WorldWritable bool   `json:"world_writable"`
}

type HostSuid struct {
	Items []SuidItem `json:"items"`
	Error string     `json:"error,omitempty"`
}

type SuidItem struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"`
}

type HostProcess struct {
	Top     []ProcessTopEntry `json:"top"`
	Signals *ProcessSignals   `json:"signals,omitempty"`
	Error   string            `json:"error,omitempty"`
}

type ProcessTopEntry struct {
	Pid    int32   `json:"pid"`
	Name   string  `json:"name"`
	User   string  `json:"user"`
	CpuPct float64 `json:"cpu_pct"`
	RssMb  float64 `json:"rss_mb"`
}

type ProcessSignals struct {
	InterpreterPython  int `json:"interpreter_python,omitempty"`
	InterpreterNode    int `json:"interpreter_node,omitempty"`
	InterpreterJava    int `json:"interpreter_java,omitempty"`
	UnknownHashWorkers int `json:"unknown_hash_workers,omitempty"`
}

type HostRuntimes struct {
	Items   []RuntimeEntry          `json:"items"`
	Docker  *DockerHostFingerprint  `json:"docker,omitempty"`
	Kubelet *KubeletNodeFingerprint `json:"kubelet,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// DockerHostFingerprint is non-secret Docker daemon posture (CIS-style hints).
type DockerHostFingerprint struct {
	DockerCliPath         string `json:"docker_cli_path,omitempty"`
	DaemonJSONPath        string `json:"daemon_json_path,omitempty"`
	LiveRestore           *bool  `json:"live_restore,omitempty"`
	Icc                   *bool  `json:"icc,omitempty"`
	UserlandProxy         *bool  `json:"userland_proxy,omitempty"`
	TlsInDaemonJSON       *bool  `json:"tls_in_daemon_json,omitempty"`
	TlsVerifyInDaemonJSON *bool  `json:"tls_verify_in_daemon_json,omitempty"`
	ContainerCount        *int   `json:"container_count,omitempty"`
	RootlessHint          string `json:"rootless_hint,omitempty"`
	DockerSockPath        string `json:"docker_sock_path,omitempty"`
	DockerSockModeOctal   string `json:"docker_sock_mode_octal,omitempty"`
	DockerSockOwnerUID    *int   `json:"docker_sock_owner_uid,omitempty"`
	DockerSockGroupGID    *int   `json:"docker_sock_group_gid,omitempty"`
	Error                 string `json:"error,omitempty"`
}

// KubeletNodeFingerprint captures bounded kubelet config hints when the node runs Kubernetes.
type KubeletNodeFingerprint struct {
	KubeletBinaryPath     string   `json:"kubelet_binary_path,omitempty"`
	ConfigSourcePaths     []string `json:"config_source_paths,omitempty"`
	ReadOnlyPort          *int     `json:"read_only_port,omitempty"`
	ProtectKernelDefaults *bool    `json:"protect_kernel_defaults,omitempty"`
	AnonymousAuthEnabled  *bool    `json:"anonymous_auth_enabled,omitempty"`
	DropInExecSampleLines []string `json:"drop_in_exec_sample_lines,omitempty"`
	Error                 string   `json:"error,omitempty"`
}

type RuntimeEntry struct {
	Kind       string `json:"kind"`
	Version    string `json:"version"`
	BinaryPath string `json:"binary_path"`
	ManagedBy  string `json:"managed_by"`
}

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

func AgentUtcRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
