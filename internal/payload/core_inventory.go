package payload

// §1 core system inventory blocks (issue #102).

// GrubSnapshot is parsed /etc/default/grub (and optional readable grub.cfg path); no secret values.
type GrubSnapshot struct {
	DefaultGrubPath          string `json:"default_grub_path,omitempty"`
	GrubCmdlineLinux         string `json:"grub_cmdline_linux,omitempty"`
	GrubTimeout              string `json:"grub_timeout,omitempty"`
	PasswordReferencePresent bool   `json:"password_reference_present"`
	GrubCfgReadablePath      string `json:"grub_cfg_readable_path,omitempty"`
	Error                    string `json:"error,omitempty"`
}

// FirmwareBoot hints UEFI vs BIOS without requiring root.
type FirmwareBoot struct {
	BootMode           string `json:"boot_mode"`
	EfiSysfsPresent    bool   `json:"efi_sysfs_present"`
	EfibootmgrExitZero bool   `json:"efibootmgr_exit_zero,omitempty"`
	Error              string `json:"error,omitempty"`
}

// SystemdHealth is get-default / is-system-running / failed units (bounded).
type SystemdHealth struct {
	SystemdPresent   bool   `json:"systemd_present"`
	DefaultTarget    string `json:"default_target,omitempty"`
	IsSystemRunning  string `json:"is_system_running,omitempty"`
	FailedUnitsCount *int   `json:"failed_units_count,omitempty"`
	LegacyRunlevel   string `json:"legacy_runlevel,omitempty"`
	Error            string `json:"error,omitempty"`
}

// SysctlKV is one sysctl key (dotted) and live string from /proc/sys.
type SysctlKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SysctlLiveBlock is a bounded CIS/STIG-style allowlist read from /proc/sys.
type SysctlLiveBlock struct {
	Items []SysctlKV `json:"items"`
	Error string     `json:"error,omitempty"`
}

// SysctlDriftEntry compares file-based sysctl vs live kernel.
type SysctlDriftEntry struct {
	Key       string `json:"key"`
	FileValue string `json:"file_value,omitempty"`
	LiveValue string `json:"live_value,omitempty"`
}

// SysctlOverlayBlock parses sysctl.conf / sysctl.d and detects drift vs live.
type SysctlOverlayBlock struct {
	ParsedFiles []string           `json:"parsed_files,omitempty"`
	Drift       []SysctlDriftEntry `json:"drift,omitempty"`
	Error       string             `json:"error,omitempty"`
}

// KernelModulesBlock lists loaded modules (capped) with optional denylist hits.
type KernelModulesBlock struct {
	Names           []string `json:"names"`
	DenylistMatches []string `json:"denylist_matches,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// SelinuxApparmorBlock reports MAC posture (no policy dump).
type SelinuxApparmorBlock struct {
	SelinuxMode     string `json:"selinux_mode,omitempty"`
	ApparmorSummary string `json:"apparmor_summary,omitempty"`
	Error           string `json:"error,omitempty"`
}

// HighRiskProcessSurface samples listeners and root-owned processes with exe/cmdline hints.
type HighRiskProcessSurface struct {
	Items []HighRiskProcessEntry `json:"items"`
	Error string                 `json:"error,omitempty"`
}

// HighRiskProcessEntry is one bounded process row.
type HighRiskProcessEntry struct {
	Pid           int32  `json:"pid"`
	User          string `json:"user"`
	ExePath       string `json:"exe_path,omitempty"`
	BinaryDeleted bool   `json:"binary_deleted"`
	CmdlineEmpty  bool   `json:"cmdline_empty"`
	ListenerPorts []int  `json:"listener_ports,omitempty"`
	Reason        string `json:"reason,omitempty"`
}
