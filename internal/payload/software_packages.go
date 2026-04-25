package payload

// Types for components.software_packages_and_applications (ingest v1, issue #106).
// Numbering aligns with internal-doc/competitors-audited-features-for-agent.md (§5 in that checklist).

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
	Version        *string `json:"version"`
	DistroVersion  *string `json:"distro_version,omitempty"`
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

// NginxPosture is allowlisted nginx security posture from -v/-V/-T (no raw secrets).
type NginxPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path,omitempty"`
	Version        *string `json:"version,omitempty"`
	DistroVersion  *string `json:"distro_version,omitempty"`
	ServiceState *string `json:"service_state,omitempty"` // running | stopped | not_installed

	SiteMapSummary *NginxSiteMapSummary `json:"site_map_summary,omitempty"`
	ListenBindings []NginxListenBinding `json:"listen_bindings,omitempty"`
	// ListenBindingDiscrepancies compares config listens to same-scan TCP listeners (nginx/openresty process) when available.
	ListenBindingDiscrepancies []string `json:"listen_binding_discrepancies,omitempty"`

	// ModulesSample is security-relevant nginx -V flags (broad); RiskyModulesCompiled is the high-risk subset only.
	ModulesSample         []string `json:"modules_sample,omitempty"`
	RiskyModulesCompiled  []string `json:"risky_modules_compiled,omitempty"`
	TlsLegacyProtocolsPresent *bool `json:"tls_legacy_protocols_present,omitempty"`

	SslConfigured            *bool   `json:"ssl_configured,omitempty"`
	SslProtocols             *string `json:"ssl_protocols,omitempty"`
	SslCiphers               *string `json:"ssl_ciphers,omitempty"`
	SslCiphersWeakPatterns   *bool   `json:"ssl_ciphers_weak_patterns,omitempty"`
	SslPreferServerCiphers   *string `json:"ssl_prefer_server_ciphers,omitempty"`
	HstsHeader               *string `json:"hsts_header,omitempty"`
	HttpToHttpsRedirect      *bool   `json:"http_to_https_redirect,omitempty"`
	SslStapling              *bool   `json:"ssl_stapling,omitempty"`
	SslSessionTicketsSummary *string `json:"ssl_session_tickets_summary,omitempty"`

	ServerTokens *string `json:"server_tokens,omitempty"`

	StubStatusUnrestricted *bool `json:"stub_status_unrestricted,omitempty"`
	ServerHeaderHidden     *bool `json:"server_header_hidden,omitempty"`
	ErrorPageCustom        *bool `json:"error_page_custom,omitempty"`

	MissingSecurityHeaders          []string `json:"missing_security_headers,omitempty"`
	LocationsDroppingParentHeaders  []string `json:"locations_dropping_parent_headers,omitempty"`

	AutoindexEnabledPaths      []string `json:"autoindex_enabled_paths,omitempty"`
	SensitivePathsUnrestricted   []string `json:"sensitive_paths_unrestricted,omitempty"`
	LimitReqConfigured         *bool    `json:"limit_req_configured,omitempty"`
	ClientMaxBodySize          *string  `json:"client_max_body_size,omitempty"`

	ProxyPassOrUpstreamSeen *bool `json:"proxy_pass_or_upstream_seen,omitempty"`
	ProxyHeadersForwarded     *bool `json:"proxy_headers_forwarded,omitempty"`
	ProxyHostHeader           *bool `json:"proxy_host_header,omitempty"`
	UpstreamPlaintext         *bool `json:"upstream_plaintext,omitempty"`
	ProxyInterceptErrors      *bool `json:"proxy_intercept_errors,omitempty"`

	RunUser                 *string `json:"run_user,omitempty"`
	RunUserWorkersNonRoot   *bool   `json:"run_user_workers_non_root,omitempty"`
	ConfigFilePermissions   *string `json:"config_file_permissions,omitempty"`
	DocrootWorldWritable    *bool   `json:"docroot_world_writable,omitempty"`
	IsContainerized         *bool   `json:"is_containerized,omitempty"`

	CollectorWarnings []string `json:"collector_warnings,omitempty"`
	Error             string   `json:"error,omitempty"`
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
	Version        *string `json:"version"`
	DistroVersion  *string `json:"distro_version,omitempty"`
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

// FtpPosture is bounded FTP server security posture (vsftpd, ProFTPD, Pure-FTPd).
// No credentials, no user lists, no file contents.
type FtpPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path"`
	Daemon       string  `json:"daemon"`
	Version        *string `json:"version"`
	DistroVersion  *string `json:"distro_version,omitempty"`
	ServiceState *string `json:"service_state"`

	AnonymousEnabled *bool   `json:"anonymous_enabled"`
	TlsEnabled       *bool   `json:"tls_enabled"`
	ChrootEnabled    *bool   `json:"chroot_enabled"`
	ListenAddress    *string `json:"listen_address"`
	ListenPort       *string `json:"listen_port"`
	PasvMinPort      *string `json:"pasv_min_port"`
	PasvMaxPort      *string `json:"pasv_max_port"`

	CollectorWarnings []string `json:"collector_warnings"`
	Error             string   `json:"error,omitempty"`
}

// RedisPosture is bounded Redis server security posture.
// No keyspace data, no ACL contents, no credential values.
type RedisPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path"`
	Version        *string `json:"version"`
	DistroVersion  *string `json:"distro_version,omitempty"`
	ServiceState *string `json:"service_state"`

	Bind               *string `json:"bind"`
	Port               *int    `json:"port"`
	ProtectedMode      *bool   `json:"protected_mode"`
	RequirepassPresent *bool   `json:"requirepass_present"`
	TlsEnabled         *bool   `json:"tls_enabled"`

	CollectorWarnings []string `json:"collector_warnings"`
	Error             string   `json:"error,omitempty"`
}

// MysqlPosture is MySQL/MariaDB security posture from binary, bounded cnf parse (includes !include/!includedir), proc, and ss (no SQL).
type MysqlPosture struct {
	Detected      bool    `json:"detected"`
	Engine        string  `json:"engine"`
	Version       *string `json:"version"`
	DistroVersion *string `json:"distro_version,omitempty"`
	BinPath       string  `json:"bin_path"`
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

// PostgresPosture is PostgreSQL security posture without SQL (merged postgresql.conf, pg_hba rules, process/fs checks).
type PostgresPosture struct {
	Detected      bool    `json:"detected"`
	Version       *string `json:"version,omitempty"`
	DistroVersion *string `json:"distro_version,omitempty"`
	BinPath       string  `json:"bin_path,omitempty"`
	ServiceState *string `json:"service_state,omitempty"`

	ListenAddresses             *string  `json:"listen_addresses,omitempty"`
	Port                        *int     `json:"port,omitempty"`
	ListenImpliesAllAddresses   *bool    `json:"listen_implies_all_addresses,omitempty"`
	PortListenerDiscrepancies   []string `json:"port_listener_discrepancies,omitempty"`
	ConfigFilePath              *string  `json:"config_file_path,omitempty"`
	PgHbaFilePath               *string  `json:"pg_hba_file_path,omitempty"`

	TrustRules             []string `json:"trust_rules,omitempty"`
	PasswordCleartextRules []string `json:"password_cleartext_rules,omitempty"`
	Md5RulesCount          *int     `json:"md5_rules_count,omitempty"`
	ScramSha256RulesCount  *int     `json:"scram_sha_256_rules_count,omitempty"`
	WideOpenRules          []string `json:"wide_open_rules,omitempty"`
	HostnosslRulesCount    *int     `json:"hostnossl_rules_count,omitempty"`
	HostRuleCount          *int     `json:"host_rule_count,omitempty"`
	HostsslRuleCount       *int     `json:"hostssl_rule_count,omitempty"`
	LocalRuleCount         *int     `json:"local_rule_count,omitempty"`
	RejectMethodCount      *int     `json:"reject_method_count,omitempty"`
	PeerOrIdentMethodCount *int     `json:"peer_or_ident_method_count,omitempty"`
	RuleOrderRisk          *bool    `json:"rule_order_risk,omitempty"`
	HbaLinesScanned        *int     `json:"hba_lines_scanned,omitempty"`

	Ssl                       *string `json:"ssl,omitempty"`
	SslCertFile               *string `json:"ssl_cert_file,omitempty"`
	SslKeyFile                *string `json:"ssl_key_file,omitempty"`
	SslMinProtocolVersion     *string `json:"ssl_min_protocol_version,omitempty"`
	SslCiphers                *string `json:"ssl_ciphers,omitempty"`
	SslCiphersWeakPatterns    *bool   `json:"ssl_ciphers_weak_patterns,omitempty"`
	SslKeyPermissions         *string `json:"ssl_key_permissions,omitempty"`
	SslMinProtocolWeakOrUnset *bool   `json:"ssl_min_protocol_weak_or_unset,omitempty"`

	LogConnections            *string `json:"log_connections,omitempty"`
	LogDisconnections         *string `json:"log_disconnections,omitempty"`
	LogStatement              *string `json:"log_statement,omitempty"`
	PasswordEncryption        *string `json:"password_encryption,omitempty"`
	SharedPreloadLibraries    *string `json:"shared_preload_libraries,omitempty"`
	PreloadAuditTrailPresent  *bool   `json:"preload_audit_trail_present,omitempty"`
	PasswordEncryptionWeakMd5 *bool   `json:"password_encryption_weak_md5,omitempty"`

	MaxConnections                  *int    `json:"max_connections,omitempty"`
	SuperuserReservedConnections    *int    `json:"superuser_reserved_connections,omitempty"`
	TcpKeepalivesIdle               *string `json:"tcp_keepalives_idle,omitempty"`
	StatementTimeout                *string `json:"statement_timeout,omitempty"`
	IdleInTransactionSessionTimeout *string `json:"idle_in_transaction_session_timeout,omitempty"`

	RunUser               *string `json:"run_user,omitempty"`
	DataDirectory         *string `json:"data_directory,omitempty"`
	DatadirPermissions    *string `json:"datadir_permissions,omitempty"`
	PgHbaPermissions      *string `json:"pg_hba_permissions,omitempty"`
	ConfigFilePermissions *string `json:"config_file_permissions,omitempty"`
	IsContainerized       *bool   `json:"is_containerized,omitempty"`

	CollectorWarnings       []string `json:"collector_warnings,omitempty"`
	LimitedWithoutSQLAccess []string `json:"limited_without_sql_access,omitempty"`
	Error                   string   `json:"error,omitempty"`
}

// DockerPosture is Docker engine security posture from read-only docker CLI and filesystem checks.
type DockerPosture struct {
	Detected bool `json:"detected"`

	DockerCliPath   *string `json:"docker_cli_path,omitempty"`
	Version         *string `json:"version,omitempty"`
	DistroVersion   *string `json:"distro_version,omitempty"`
	APIVersion      *string `json:"api_version,omitempty"`
	StorageDriver   *string `json:"storage_driver,omitempty"`
	ContainerCount  *int    `json:"container_count,omitempty"`
	DockerRootDir   *string `json:"docker_root_dir,omitempty"`

	RootlessMode        *bool   `json:"rootless_mode,omitempty"`
	DockerSockPath      *string `json:"docker_sock_path,omitempty"`
	DockerSockModeOctal *string `json:"docker_sock_mode_octal,omitempty"`
	DockerSockOwnerUID  *int    `json:"docker_sock_owner_uid,omitempty"`
	DockerSockGroupGID  *int    `json:"docker_sock_group_gid,omitempty"`

	DockerSockMountedInContainers []string `json:"docker_sock_mounted_in_containers,omitempty"`

	TCPAPIExposed    *bool   `json:"tcp_api_exposed,omitempty"`
	TCPAPIAddress    *string `json:"tcp_api_address,omitempty"`
	TCPAPITLSEnabled *bool   `json:"tcp_api_tls_enabled,omitempty"`

	UsernsRemap     *string `json:"userns_remap,omitempty"`
	NoNewPrivileges *bool   `json:"no_new_privileges,omitempty"`
	IccEnabled      *bool   `json:"icc_enabled,omitempty"`
	LiveRestore     *bool   `json:"live_restore,omitempty"`
	LogDriver       *string `json:"log_driver,omitempty"`
	SeccompProfile  *string `json:"seccomp_profile,omitempty"`
	DefaultUlimits  *string `json:"default_ulimits,omitempty"`

	ContainerRisks []DockerContainerRisk `json:"container_risks,omitempty"`

	ImagesRunningAsLatest    []string `json:"images_running_as_latest,omitempty"`
	ImagesWithoutHealthcheck []string `json:"images_without_healthcheck,omitempty"`

	PublishedPorts          []DockerPublishedPort            `json:"published_ports,omitempty"`
	CustomNetworksEncrypted []DockerOverlayNetworkEncryption `json:"custom_networks_encrypted,omitempty"`

	DockerGroupMembers    []string `json:"docker_group_members,omitempty"`
	DockerDataPermissions *string  `json:"docker_data_permissions,omitempty"`
	KernelVersion         *string  `json:"kernel_version,omitempty"`
	IsSwarmActive         *bool    `json:"is_swarm_active,omitempty"`

	CollectorWarnings []string `json:"collector_warnings,omitempty"`
	Error             string   `json:"error,omitempty"`
}

// DockerContainerRisk is one running container with at least one security flag (omit clean containers from the list).
type DockerContainerRisk struct {
	Name                   string   `json:"name"`
	ID                     string   `json:"id"`
	Privileged             *bool    `json:"privileged,omitempty"`
	PidModeHost            *bool    `json:"pid_mode_host,omitempty"`
	NetworkModeHost        *bool    `json:"network_mode_host,omitempty"`
	CapabilitiesAdded      []string `json:"capabilities_added,omitempty"`
	CapabilitiesNotDropped *bool    `json:"capabilities_not_dropped,omitempty"`
	RunsAsRoot             *bool    `json:"runs_as_root,omitempty"`
	WritableRootfs         *bool    `json:"writable_rootfs,omitempty"`
	SensitiveMounts        []string `json:"sensitive_mounts,omitempty"`
	NoSecurityProfile      *bool    `json:"no_security_profile,omitempty"`
	NoResourceLimits       *bool    `json:"no_resource_limits,omitempty"`
}

// DockerPublishedPort is one published port binding from a running container.
type DockerPublishedPort struct {
	Container           string `json:"container"`
	ContainerID         string `json:"container_id"`
	HostIP              string `json:"host_ip"`
	HostPort            string `json:"host_port"`
	ContainerPort       string `json:"container_port"`
	Protocol            string `json:"protocol"`
	BindAllInterfaces   bool   `json:"bind_all_interfaces"`
}

// DockerOverlayNetworkEncryption records overlay driver encryption hint for a user-defined network.
type DockerOverlayNetworkEncryption struct {
	NetworkName string `json:"network_name"`
	Encrypted   bool   `json:"encrypted"`
}

// MongodbPosture is bounded MongoDB server security posture.
// No database contents, user lists, or credentials.
type MongodbPosture struct {
	Detected     bool    `json:"detected"`
	BinPath      string  `json:"bin_path"`
	Version        *string `json:"version"`
	DistroVersion  *string `json:"distro_version,omitempty"`
	ServiceState *string `json:"service_state"`

	BindIp         *string `json:"bind_ip"`
	Port           *int    `json:"port"`
	TlsMode        *string `json:"tls_mode"`
	AuthEnabled    *bool   `json:"auth_enabled"`
	KeyFilePresent *bool   `json:"key_file_present"`
	JournalEnabled *bool   `json:"journal_enabled"`

	CollectorWarnings []string `json:"collector_warnings"`
	Error             string   `json:"error,omitempty"`
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
