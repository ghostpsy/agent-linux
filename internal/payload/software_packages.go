package payload

// Types for components.software_packages_and_applications (ingest v1, issue #106).
// Numbering aligns with doc/competitors-audited-features-for-agent.md (§5 in that checklist).

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

// ApacheHttpdPosture is allowlisted httpd/apache2 security posture (no secrets, no full raw config dump).
type ApacheHttpdPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path"`
	Version      *string `json:"version"`
	ServiceState *string `json:"service_state"`

	ListenBindings             []ApacheListenBinding `json:"listen_bindings"`
	ListenBindingDiscrepancies   []string              `json:"listen_binding_discrepancies"`

	SSLModuleLoaded     *bool   `json:"ssl_module_loaded"`
	SSLProtocol         *string `json:"ssl_protocol"`
	SSLCipherSuite      *string `json:"ssl_cipher_suite"`
	HstsHeader          *string `json:"hsts_header"`
	HTTPToHTTPSRedirect *bool   `json:"http_to_https_redirect"`

	RiskyModulesLoaded       []string `json:"risky_modules_loaded"`
	ProtectiveModulesMissing []string `json:"protective_modules_missing"`

	ServerTokens               *string  `json:"server_tokens"`
	ServerSignature            *string  `json:"server_signature"`
	TraceEnabled               *bool    `json:"trace_enabled"`
	SensitivePathsUnrestricted []string `json:"sensitive_paths_unrestricted"`

	IndexesEnabledPaths             []string `json:"indexes_enabled_paths"`
	FollowSymlinksUnrestrictedPaths []string `json:"follow_symlinks_unrestricted_paths"`
	AllowOverrideAllPaths           []string `json:"allow_override_all_paths"`

	MissingSecurityHeaders []string `json:"missing_security_headers"`

	RunUser              *string `json:"run_user"`
	DocrootWorldWritable *bool   `json:"docroot_world_writable"`
	IsContainerized      *bool   `json:"is_containerized"`

	OpenForwardProxy *bool `json:"open_forward_proxy"`

	CollectorWarnings []string `json:"collector_warnings"`

	VhostsSummary *ApacheVhostsSummary `json:"vhosts_summary"`
	Error         string               `json:"error,omitempty"`
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

// PostfixPosture is allowlisted postconf + bounded master.cf security posture (no postconf -n dump, no queue or mail content).
type PostfixPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path"`
	Version      *string `json:"version"`
	ServiceState *string `json:"service_state"`

	ListenAddresses *string `json:"listen_addresses"`
	ListenProtocols *string `json:"listen_protocols"`

	Mynetworks                 *string `json:"mynetworks"`
	SmtpdRelayRestrictions     *string `json:"smtpd_relay_restrictions"`
	RelayDomains               *string `json:"relay_domains"`
	SmtpdRecipientRestrictions *string `json:"smtpd_recipient_restrictions"`

	SmtpdTlsSecurityLevel     *string `json:"smtpd_tls_security_level"`
	SmtpTlsSecurityLevel      *string `json:"smtp_tls_security_level"`
	SmtpdTlsProtocols         *string `json:"smtpd_tls_protocols"`
	SmtpdTlsMandatoryCiphers  *string `json:"smtpd_tls_mandatory_ciphers"`
	TlsPreemptCipherlist      *bool   `json:"tls_preempt_cipherlist"`

	SmtpdSaslAuthEnable        *bool   `json:"smtpd_sasl_auth_enable"`
	SmtpdSaslSecurityOptions   *string `json:"smtpd_sasl_security_options"`
	SmtpdTlsAuthOnly           *bool   `json:"smtpd_tls_auth_only"`
	SubmissionPortEnabled      *bool   `json:"submission_port_enabled"`

	SmtpdSenderRestrictions *string `json:"smtpd_sender_restrictions"`
	SmtpdHeloRequired       *bool   `json:"smtpd_helo_required"`
	SmtpdHeloRestrictions   *string `json:"smtpd_helo_restrictions"`
	SmtpdSenderLoginMaps    *string `json:"smtpd_sender_login_maps"`

	SmtpdBanner          *string `json:"smtpd_banner"`
	ShowqServiceExposed  *bool   `json:"showq_service_exposed"`

	SmtpdClientConnectionRateLimit *string `json:"smtpd_client_connection_rate_limit"`
	SmtpdClientMessageRateLimit    *string `json:"smtpd_client_message_rate_limit"`
	SmtpdErrorSleepTime            *string `json:"smtpd_error_sleep_time"`
	SmtpdHardErrorLimit            *string `json:"smtpd_hard_error_limit"`
	MessageSizeLimit               *string `json:"message_size_limit"`

	RunUser             *string `json:"run_user"`
	ChrootRatioSummary  *string `json:"chroot_ratio_summary"`
	IsContainerized     *bool   `json:"is_containerized"`

	CollectorWarnings []string `json:"collector_warnings"`
	Error             string   `json:"error,omitempty"`
}

// MysqlPosture is MySQL/MariaDB security posture from binary, bounded cnf parse (includes !include/!includedir), proc, and ss (no SQL).
type MysqlPosture struct {
	Detected     bool    `json:"detected"`
	Engine       string  `json:"engine"`
	Version      *string `json:"version"`
	BinPath      string  `json:"bin_path"`
	ServiceState *string `json:"service_state"`

	BindAddress        *string `json:"bind_address"`
	Port               *int    `json:"port"`
	SkipNetworking     *bool   `json:"skip_networking"`
	SocketPath         *string `json:"socket_path"`
	RuntimeListenCheck *string `json:"runtime_listen_check"`

	DefaultAuthPlugin    *string `json:"default_auth_plugin"`
	AuthSocketOrUnix     *bool   `json:"auth_socket_or_unix"`
	SecureAuth           *string `json:"secure_auth"`
	PasswordPolicyPlugin *bool   `json:"password_policy_plugin"`

	SslCa                  *string `json:"ssl_ca"`
	SslCert                *string `json:"ssl_cert"`
	SslKey                 *string `json:"ssl_key"`
	TlsConfigured          *bool   `json:"tls_configured"`
	RequireSecureTransport *string `json:"require_secure_transport"`
	TlsVersion             *string `json:"tls_version"`

	LocalInfile     *string `json:"local_infile"`
	SecureFilePriv  *string `json:"secure_file_priv"`
	SymbolicLinks   *string `json:"symbolic_links"`
	LogRaw          *string `json:"log_raw"`
	GeneralLog      *string `json:"general_log"`
	SkipGrantTables *bool   `json:"skip_grant_tables"`

	RunUser                 *string `json:"run_user"`
	Datadir                 *string `json:"datadir"`
	DatadirPermissions      *string `json:"datadir_permissions"`
	ConfigFilePermissions   *string `json:"config_file_permissions"`
	MyCnfPasswordsExposed   *bool   `json:"my_cnf_passwords_exposed"`
	ErrorLogPermissions     *string `json:"error_log_permissions"`
	IsContainerized         *bool   `json:"is_containerized"`

	InnodbEncryptTables    *string `json:"innodb_encrypt_tables"`
	DefaultTableEncryption *string `json:"default_table_encryption"`
	KeyringPlugin          *bool   `json:"keyring_plugin"`

	CollectorWarnings       []string `json:"collector_warnings"`
	LimitedWithoutSQLAccess []string `json:"limited_without_sql_access"`
	Error                   string   `json:"error,omitempty"`
}

// PostgresPosture is bounded PostgreSQL server metadata (no SQL; pg_hba as aggregate counts only).
type PostgresPosture struct {
	Detected     bool                 `json:"detected"`
	Version      string               `json:"version,omitempty"`
	BinPath      string               `json:"bin_path,omitempty"`
	ServiceState string               `json:"service_state,omitempty"`
	ListenHints  *PostgresListenHints `json:"listen_hints,omitempty"`
	HbaHints     *PostgresHbaHints    `json:"hba_hints,omitempty"`
	Error        string               `json:"error,omitempty"`
}

// PostgresListenHints summarizes postgresql.conf keys from a bounded read.
type PostgresListenHints struct {
	ListenAddresses           string `json:"listen_addresses,omitempty"`
	Port                      *int   `json:"port,omitempty"`
	Ssl                       string `json:"ssl,omitempty"`
	ConfigPathUsed            string `json:"config_path_used,omitempty"`
	ListenImpliesAllAddresses *bool  `json:"listen_implies_all_addresses,omitempty"`
}

// PostgresHbaHints summarizes pg_hba.conf rule types and auth methods (counts only—no DB/user/address literals).
type PostgresHbaHints struct {
	FilePathUsed              string `json:"file_path_used,omitempty"`
	LinesScanned              int    `json:"lines_scanned"`
	HostRuleCount             int    `json:"host_rule_count"`
	HostsslRuleCount          int    `json:"hostssl_rule_count"`
	HostnosslRuleCount        int    `json:"hostnossl_rule_count"`
	LocalRuleCount            int    `json:"local_rule_count"`
	TrustMethodCount          int    `json:"trust_method_count"`
	RejectMethodCount         int    `json:"reject_method_count"`
	PasswordFamilyMethodCount int    `json:"password_family_method_count"`
	PeerOrIdentMethodCount    int    `json:"peer_or_ident_method_count"`
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
