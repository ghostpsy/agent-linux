package payload

// MountOptionsAudit compares fstab and live mount options for standard hardening paths.
type MountOptionsAudit struct {
	Paths []MountPathSignals `json:"paths,omitempty"`
	Error string             `json:"error,omitempty"`
}

// MountPathSignals reports nodev/nosuid/noexec from live mounts (preferred) or fstab.
type MountPathSignals struct {
	Mountpoint       string `json:"mountpoint"`
	InFstab          bool   `json:"in_fstab"`
	FstabOptions     string `json:"fstab_options,omitempty"`
	LiveMountOptions string `json:"live_mount_options,omitempty"`
	Nodev            bool   `json:"nodev"`
	Nosuid           bool   `json:"nosuid"`
	Noexec           bool   `json:"noexec"`
}

// PathPermissionsAudit extends path posture: sticky /tmp, WW dirs, SGID, unowned samples.
type PathPermissionsAudit struct {
	TmpStickyBitPresent     *bool      `json:"tmp_sticky_bit_present,omitempty"`
	WorldWritableDirsSample []string   `json:"world_writable_dirs_sample,omitempty"`
	SgidItemsSample         []SgidItem `json:"sgid_items_sample,omitempty"`
	UnownedFilesSample      []string   `json:"unowned_files_sample,omitempty"`
	Error                   string     `json:"error,omitempty"`
}

// SgidItem is a bounded setgid file entry (same shape idea as SuidItem).
type SgidItem struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"`
}

// UsbStoragePosture reports usb_storage module and modprobe blacklist hints.
type UsbStoragePosture struct {
	UsbStorageLoaded               bool     `json:"usb_storage_loaded"`
	BlacklistUsbStorageLinePresent bool     `json:"blacklist_usb_storage_line_present"`
	ModprobeFragmentLinesSample    []string `json:"modprobe_fragment_lines_sample,omitempty"`
	Error                          string   `json:"error,omitempty"`
}

// FileIntegrityTooling detects AIDE/Tripwire-style tooling without uploading databases.
type FileIntegrityTooling struct {
	AideSuspected      bool     `json:"aide_suspected"`
	TripwireSuspected  bool     `json:"tripwire_suspected"`
	EvidencePaths      []string `json:"evidence_paths,omitempty"`
	SystemdUnitsSample []string `json:"systemd_units_sample,omitempty"`
	LatestDbUtcHint    string   `json:"latest_db_utc_hint,omitempty"`
	Error              string   `json:"error,omitempty"`
}

// CryptStorageHint summarizes crypttab and lsblk crypt volumes (no keys).
type CryptStorageHint struct {
	CrypttabReadable          bool     `json:"crypttab_readable"`
	CrypttabEntryCount        int      `json:"crypttab_entry_count"`
	CrypttabMapperNamesSample []string `json:"crypttab_mapper_names_sample,omitempty"`
	LsblkCryptVolumeCount     int      `json:"lsblk_crypt_volume_count"`
	LsblkCryptNamesSample     []string `json:"lsblk_crypt_names_sample,omitempty"`
	Error                     string   `json:"error,omitempty"`
}

// NfsExportsFingerprint summarizes /etc/exports with hashed paths (no raw export paths).
type NfsExportsFingerprint struct {
	ExportsReadable bool             `json:"exports_readable"`
	Entries         []NfsExportEntry `json:"entries,omitempty"`
	Error           string           `json:"error,omitempty"`
}

// NfsExportEntry is one export line fingerprint (path hashed).
type NfsExportEntry struct {
	Index                      int    `json:"index"`
	PathHash                   string `json:"path_hash"`
	CombinedOptionsFingerprint string `json:"combined_options_fingerprint"`
	HasNoRootSquash            bool   `json:"has_no_root_squash"`
	HasRootSquash              bool   `json:"has_root_squash"`
	SecModeHint                string `json:"sec_mode_hint,omitempty"`
}
