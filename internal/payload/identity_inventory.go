package payload

// ShadowAccountSummary is non-secret metadata from /etc/shadow (no hash material).
type ShadowAccountSummary struct {
	ShadowReadable                   bool   `json:"shadow_readable"`
	AccountsLockedCount              int    `json:"accounts_locked_count"`
	AccountsNoLoginPasswordCount     int    `json:"accounts_no_login_password_count"`
	AccountsPasswordExpiredHintCount int    `json:"accounts_password_expired_hint_count"`
	AccountsNeverLoggedInHintCount   int    `json:"accounts_never_logged_in_hint_count"`
	Error                            string `json:"error,omitempty"`
}

// DuplicateIDEntry lists a numeric ID shared by more than one account (names capped for audit).
type DuplicateIDEntry struct {
	ID    int      `json:"id"`
	Names []string `json:"names"`
}

// DuplicateUidGid reports passwd/group collisions (bounded names per ID).
type DuplicateUidGid struct {
	DuplicateUidCount int                `json:"duplicate_uid_count"`
	DuplicateGidCount int                `json:"duplicate_gid_count"`
	DuplicateUids     []DuplicateIDEntry `json:"duplicate_uids,omitempty"`
	DuplicateGids     []DuplicateIDEntry `json:"duplicate_gids,omitempty"`
	Error             string             `json:"error,omitempty"`
}

// PwqualityKV is one non-secret pwquality.conf assignment.
type PwqualityKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PasswordPolicyFingerprint reads pwquality.conf and PAM password stack lines (no secrets).
type PasswordPolicyFingerprint struct {
	PwqualityKeys             []PwqualityKV `json:"pwquality_keys,omitempty"`
	PamPasswordRequisiteLines []string      `json:"pam_password_requisite_lines,omitempty"`
	Error                     string        `json:"error,omitempty"`
}

// SudoersAudit is structural sudoers signal without transmitting full rule bodies.
type SudoersAudit struct {
	FilesScanned                     []string `json:"files_scanned,omitempty"`
	NopasswdMentionCount             int      `json:"nopasswd_mention_count"`
	AllAllPatternCount               int      `json:"all_all_pattern_count"`
	WildcardRiskLineCount            int      `json:"wildcard_risk_line_count"`
	IncludedirCount                  int      `json:"includedir_count"`
	DefaultsRequirettyPresent        bool     `json:"defaults_requiretty_present"`
	DefaultsUsePtyPresent            bool     `json:"defaults_use_pty_present"`
	DefaultsVisiblepwInvertedPresent bool     `json:"defaults_visiblepw_inverted_present"`
	Error                            string   `json:"error,omitempty"`
}
