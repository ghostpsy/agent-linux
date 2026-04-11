package payload

// §9 security frameworks and malware defense (Lynis-aligned inventory).

// SecurityFrameworksAndMalwareDefenseComponent holds MAC deep posture, malware-scanner hints, and fail2ban inventory.
type SecurityFrameworksAndMalwareDefenseComponent struct {
	MacDeepPosture         *MacDeepPosture         `json:"mac_deep_posture,omitempty"`
	MalwareScannersPosture *MalwareScannersPosture `json:"malware_scanners_posture,omitempty"`
	Fail2banPosture        *Fail2banPosture        `json:"fail2ban_posture,omitempty"`
}

// MacDeepPosture extends §1 MAC summary when SELinux is enforcing and AppArmor tools exist.
type MacDeepPosture struct {
	SelinuxPsZLineSampleCap         *int     `json:"selinux_ps_z_line_sample_cap,omitempty"`
	SelinuxPsZUnconfinedLikeCount   *int     `json:"selinux_ps_z_unconfined_like_count,omitempty"`
	SelinuxSemanagePermissiveSample []string `json:"selinux_semanage_permissive_sample,omitempty"`
	SelinuxSemanageUnavailable      string   `json:"selinux_semanage_unavailable,omitempty"`
	ApparmorProfilesEnforceCount    *int     `json:"apparmor_profiles_enforce_count,omitempty"`
	ApparmorProfilesComplainCount   *int     `json:"apparmor_profiles_complain_count,omitempty"`
	ApparmorStatusUnavailable       string   `json:"apparmor_status_unavailable,omitempty"`
	Error                           string   `json:"error,omitempty"`
}

// MalwareScannersPosture reports scanner presence, version strings, and coarse freshness hints only.
type MalwareScannersPosture struct {
	Scanners []MalwareScannerEntry `json:"scanners,omitempty"`
	Error    string                `json:"error,omitempty"`
}

// MalwareScannerEntry is one detected scanner or commercial agent unit (no scan execution).
type MalwareScannerEntry struct {
	ID              string `json:"id"`
	Detected        bool   `json:"detected"`
	VersionSummary  string `json:"version_summary,omitempty"`
	LastUpdateHint  string `json:"last_update_hint,omitempty"`
	UnitActiveState string `json:"unit_active_state,omitempty"`
	UnitFile        string `json:"unit_file,omitempty"`
}

// Fail2banPosture reports fail2ban presence and bounded jail config hints (file-based only).
type Fail2banPosture struct {
	Present              bool     `json:"present"`
	UnitActiveState      string   `json:"unit_active_state,omitempty"`
	UnitFileState        string   `json:"unit_file_state,omitempty"`
	Fail2banClientPath   string   `json:"fail2ban_client_path,omitempty"`
	VersionSummary       string   `json:"version_summary,omitempty"`
	ConfigPathsRead      []string `json:"config_paths_read,omitempty"`
	EnabledJails         []string `json:"enabled_jails,omitempty"`
	JailSectionCountHint *int     `json:"jail_section_count_hint,omitempty"`
	DefaultBantime       string   `json:"default_bantime,omitempty"`
	DefaultFindtime      string   `json:"default_findtime,omitempty"`
	DefaultMaxRetry      string   `json:"default_maxretry,omitempty"`
	Error                string   `json:"error,omitempty"`
}
