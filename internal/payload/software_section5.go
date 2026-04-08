package payload

// §5 software packages and applications inventory blocks (ingest v1, issue #106).

// WebDbServersFingerprint captures bounded web/DB server config hints (no secrets).
type WebDbServersFingerprint struct {
	NginxServerTokens         string `json:"nginx_server_tokens,omitempty"`
	NginxConfigPathUsed       string `json:"nginx_config_path_used,omitempty"`
	ApacheServerTokens        string `json:"apache_server_tokens,omitempty"`
	ApacheServerSignature     string `json:"apache_server_signature,omitempty"`
	ApacheConfigPathUsed      string `json:"apache_config_path_used,omitempty"`
	MysqlBindAddress          string `json:"mysql_bind_address,omitempty"`
	MysqlConfigPathUsed       string `json:"mysql_config_path_used,omitempty"`
	PostgresqlListenAddresses string `json:"postgresql_listen_addresses,omitempty"`
	PostgresqlSsl             string `json:"postgresql_ssl,omitempty"`
	PostgresqlConfigPathUsed  string `json:"postgresql_config_path_used,omitempty"`
	Error                     string `json:"error,omitempty"`
}

// RedisExposureFingerprint is non-secret redis.conf exposure hints plus unit state.
type RedisExposureFingerprint struct {
	UnitActiveState    string `json:"unit_active_state,omitempty"`
	ConfigPathUsed     string `json:"config_path_used,omitempty"`
	Bind               string `json:"bind,omitempty"`
	Port               *int   `json:"port,omitempty"`
	ProtectedMode      string `json:"protected_mode,omitempty"`
	RequirepassPresent *bool  `json:"requirepass_present,omitempty"`
	Error              string `json:"error,omitempty"`
}

// CronTimersInventory summarizes cron files, user crontabs, and systemd timers.
type CronTimersInventory struct {
	SystemCrontabLineCount    int      `json:"system_crontab_line_count"`
	SystemCrontabSample       []string `json:"system_crontab_sample,omitempty"`
	CronDropinFileNamesSample []string `json:"cron_dropin_file_names_sample,omitempty"`
	UserCrontabsPresentCount  int      `json:"user_crontabs_present_count"`
	UserCrontabUsersSample    []string `json:"user_crontab_users_sample,omitempty"`
	UserCrontabLinesSample    []string `json:"user_crontab_lines_sample,omitempty"`
	CronVarSpoolModeOctal     string   `json:"cron_var_spool_mode_octal,omitempty"`
	SystemdTimersCount        int      `json:"systemd_timers_count"`
	SystemdTimerUnitsSample   []string `json:"systemd_timer_units_sample,omitempty"`
	Error                     string   `json:"error,omitempty"`
}

// CupsExposureFingerprint is CUPS unit state and bounded config lines.
type CupsExposureFingerprint struct {
	UnitActiveState         string   `json:"unit_active_state,omitempty"`
	ListenLinesSample       []string `json:"listen_lines_sample,omitempty"`
	WebInterfaceLinesSample []string `json:"web_interface_lines_sample,omitempty"`
	Error                   string   `json:"error,omitempty"`
}

// MtaFingerprint is MTA presence and bounded relay/bind hints (no queue contents).
type MtaFingerprint struct {
	DetectedMta                              string   `json:"detected_mta,omitempty"`
	PostfixInetInterfaces                    string   `json:"postfix_inet_interfaces,omitempty"`
	PostfixMynetworksStyle                   string   `json:"postfix_mynetworks_style,omitempty"`
	PostfixSmtpdRecipientRestrictionsPresent *bool    `json:"postfix_smtpd_recipient_restrictions_present,omitempty"`
	EximConfigPath                           string   `json:"exim_config_path,omitempty"`
	EximRelayDomainsHintSample               []string `json:"exim_relay_domains_hint_sample,omitempty"`
	SendmailCfPathPresent                    *bool    `json:"sendmail_cf_path_present,omitempty"`
	SendmailLinesSample                      []string `json:"sendmail_lines_sample,omitempty"`
	Error                                    string   `json:"error,omitempty"`
}
