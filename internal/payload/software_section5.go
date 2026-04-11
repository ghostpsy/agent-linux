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

// ApacheHttpdPosture is allowlisted httpd/apache2 metadata (no full config, no secrets).
type ApacheHttpdPosture struct {
	Detected       bool                  `json:"detected"`
	Version        string                `json:"version,omitempty"`
	BinPath        string                `json:"bin_path,omitempty"`
	ServiceState   string                `json:"service_state,omitempty"`
	VhostsSummary  *ApacheVhostsSummary  `json:"vhosts_summary,omitempty"`
	ListenBindings []ApacheListenBinding `json:"listen_bindings,omitempty"`
	HardeningHints *ApacheHardeningHints `json:"hardening_hints,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// ApacheHardeningHints summarizes security-relevant directives from bounded main config + module stubs (no full tree walk).
type ApacheHardeningHints struct {
	TraceEnable             string   `json:"trace_enable,omitempty"`
	SSLProtocolSummary      string   `json:"ssl_protocol_summary,omitempty"`
	SSLCipherSuiteSummary   string   `json:"ssl_cipher_suite_summary,omitempty"`
	AllowOverrideMain       string   `json:"allow_override_main,omitempty"`
	OptionsLinesSample      []string `json:"options_lines_sample,omitempty"`
	IndexesInOptionsHint    *bool    `json:"indexes_in_options_hint,omitempty"`
	SecurityRelevantModules []string `json:"security_relevant_modules,omitempty"`
}

// ApacheVhostsSummary is vhost count plus capped server names from apache/httpd -S.
type ApacheVhostsSummary struct {
	VhostCount  int      `json:"vhost_count"`
	ServerNames []string `json:"server_names,omitempty"`
}

// ApacheListenBinding is one Listen / VirtualHost binding from -S output.
type ApacheListenBinding struct {
	Bind string `json:"bind"`
	Port int    `json:"port"`
}

// NginxPosture is allowlisted nginx metadata from -v/-V/-T (no full config, no secrets).
type NginxPosture struct {
	Detected     bool   `json:"detected"`
	Version      string `json:"version,omitempty"`
	BinPath      string `json:"bin_path,omitempty"`
	ServiceState string `json:"service_state,omitempty"`
	// ModulesSample is security-relevant nginx -V compile flags only (not full configure args); see parseNginxSecurityRelevantModules.
	ModulesSample  []string             `json:"modules_sample,omitempty"`
	SiteMapSummary *NginxSiteMapSummary `json:"site_map_summary,omitempty"`
	ListenBindings []NginxListenBinding `json:"listen_bindings,omitempty"`
	HardeningHints *NginxHardeningHints `json:"hardening_hints,omitempty"`
	Error          string               `json:"error,omitempty"`
}

// NginxSiteMapSummary counts server blocks and caps server_name tokens from parsed -T output.
type NginxSiteMapSummary struct {
	ServerBlockCount int      `json:"server_block_count"`
	ServerNames      []string `json:"server_names,omitempty"`
}

// NginxListenBinding is one listen directive (address, port, TLS-related listen flag).
type NginxListenBinding struct {
	Bind string `json:"bind"`
	Port int    `json:"port"`
	SSL  bool   `json:"ssl,omitempty"`
}

// NginxHardeningHints summarizes common hardening directives (OWASP/operator guides); no header values.
type NginxHardeningHints struct {
	ServerTokensSummary           string   `json:"server_tokens_summary,omitempty"`
	TlsProtocolsSummary           string   `json:"tls_protocols_summary,omitempty"`
	TlsLegacyProtocolsPresent     *bool    `json:"tls_legacy_protocols_present,omitempty"`
	SslPreferServerCiphersSummary string   `json:"ssl_prefer_server_ciphers_summary,omitempty"`
	SslSessionTicketsSummary      string   `json:"ssl_session_tickets_summary,omitempty"`
	SslStaplingEnabled            *bool    `json:"ssl_stapling_enabled,omitempty"`
	SecurityHeaderNamesPresent    []string `json:"security_header_names_present,omitempty"`
	RateLimitingPresent           bool     `json:"rate_limiting_present,omitempty"`
	ClientBufferLimitsPresent     bool     `json:"client_buffer_limits_present,omitempty"`
	AutoindexOnSeen               bool     `json:"autoindex_on_seen,omitempty"`
	HttpMethodRestrictionSeen     bool     `json:"http_method_restriction_seen,omitempty"`
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
