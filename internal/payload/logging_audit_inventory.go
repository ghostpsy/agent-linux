package payload

// §7 logging and system auditing inventory (competitors-audited §7).

// SyslogForwardingPosture summarizes syslog daemons and remote forwarding hints (hostnames only).
type SyslogForwardingPosture struct {
	Daemons []SyslogDaemonEntry `json:"daemons,omitempty"`
	Error   string              `json:"error,omitempty"`
}

// SyslogDaemonEntry is one syslog implementation detected on the host.
type SyslogDaemonEntry struct {
	Implementation              string   `json:"implementation"`
	UnitName                    string   `json:"unit_name,omitempty"`
	UnitActive                  string   `json:"unit_active,omitempty"`
	ConfigPathsRead             []string `json:"config_paths_read,omitempty"`
	RemoteLogHosts              []string `json:"remote_log_hosts,omitempty"`
	ForwardingRuleSampleLines   []string `json:"forwarding_rule_sample_lines,omitempty"`
}

// JournaldPosture summarizes systemd-journald config hints (no journal contents).
type JournaldPosture struct {
	UnitActive                   string `json:"unit_active,omitempty"`
	ConfigPathsRead              []string `json:"config_paths_read,omitempty"`
	Storage                      string `json:"storage,omitempty"`
	ForwardToSyslog              *bool  `json:"forward_to_syslog,omitempty"`
	ForwardToWall                *bool  `json:"forward_to_wall,omitempty"`
	ForwardToConsole             *bool  `json:"forward_to_console,omitempty"`
	Compress                     *bool  `json:"compress,omitempty"`
	Seal                         *bool  `json:"seal,omitempty"`
	SystemMaxUse                 string `json:"system_max_use,omitempty"`
	RuntimeMaxUse                string `json:"runtime_max_use,omitempty"`
	MaxRetentionSec              string `json:"max_retention_sec,omitempty"`
	JournalctlDiskUsageSummary   string `json:"journalctl_disk_usage_summary,omitempty"`
	Error                        string `json:"error,omitempty"`
}

// AuditdPosture summarizes auditd activation and rule inventory (no full rule bodies).
type AuditdPosture struct {
	UnitActive                 string               `json:"unit_active,omitempty"`
	RuleLineCount              *int                 `json:"rule_line_count,omitempty"`
	RulesDropInFiles           []AuditRulesFileHash `json:"rules_drop_in_files,omitempty"`
	AuditctlUnavailableReason  string               `json:"auditctl_unavailable_reason,omitempty"`
	Error                      string               `json:"error,omitempty"`
}

// AuditRulesFileHash is a path plus digest of an on-disk rules fragment (bounded read).
type AuditRulesFileHash struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

// LargeVarLogFileEntry is a file under /var/log at or above the agent size threshold with no matching logrotate stanza path (heuristic).
type LargeVarLogFileEntry struct {
	RelPath   string `json:"rel_path"`
	SizeBytes int64  `json:"size_bytes"`
}

// LogrotateDiskPosture summarizes logrotate configuration and /var/log mount usage (gopsutil disk.Usage).
type LogrotateDiskPosture struct {
	MainConfPresent                      bool                   `json:"main_conf_present,omitempty"`
	MainConfIncludeLinesSample           []string               `json:"main_conf_include_lines_sample,omitempty"`
	VarLogStanzaHint                     bool                   `json:"var_log_stanza_hint,omitempty"`
	VarLogDirectiveSampleLines            []string               `json:"var_log_directive_sample_lines,omitempty"`
	VarLogUsagePath                      string                 `json:"var_log_usage_path,omitempty"`
	VarLogMountUsedPct                   *int                   `json:"var_log_mount_used_pct,omitempty"`
	LogPartitionUsageHigh                *bool                  `json:"log_partition_usage_high,omitempty"`
	LargeVarLogFiles                     []LargeVarLogFileEntry `json:"large_var_log_files,omitempty"`
	LargeVarLogWithoutRotationHintCount  *int                   `json:"large_var_log_without_rotation_hint_count,omitempty"`
	Error                                string                 `json:"error,omitempty"`
}

// AtBatchPosture summarizes atd and at.allow / at.deny / spool exposure hints.
type AtBatchPosture struct {
	AtdUnitActive      string `json:"atd_unit_active,omitempty"`
	AtAllowPresent     bool   `json:"at_allow_present,omitempty"`
	AtDenyPresent      bool   `json:"at_deny_present,omitempty"`
	AtAllowModeOctal   string `json:"at_allow_mode_octal,omitempty"`
	AtDenyModeOctal    string `json:"at_deny_mode_octal,omitempty"`
	SpoolPathUsed      string `json:"spool_path_used,omitempty"`
	SpoolDirModeOctal  string `json:"spool_dir_mode_octal,omitempty"`
	Error              string `json:"error,omitempty"`
}

// ProcessAccountingPosture summarizes sysstat/sadc scheduling and ld.so.preload presence (stat only; no preload content).
type ProcessAccountingPosture struct {
	SadcOnPath              bool   `json:"sadc_on_path,omitempty"`
	SysstatCronHint         bool   `json:"sysstat_cron_hint,omitempty"`
	LdSoPreloadFilePresent  bool   `json:"ld_so_preload_file_present,omitempty"`
	LdSoPreloadPath         string `json:"ld_so_preload_path,omitempty"`
	Error                   string `json:"error,omitempty"`
}
