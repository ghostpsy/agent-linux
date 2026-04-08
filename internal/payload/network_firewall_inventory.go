package payload

// TcpWrappersFingerprint summarizes hosts.allow / hosts.deny without deep semantics.
type TcpWrappersFingerprint struct {
	HostsAllowPresent     bool     `json:"hosts_allow_present"`
	HostsDenyPresent      bool     `json:"hosts_deny_present"`
	HostsAllowLineCount   int      `json:"hosts_allow_line_count"`
	HostsDenyLineCount    int      `json:"hosts_deny_line_count"`
	HostsAllowSampleLines []string `json:"hosts_allow_sample_lines,omitempty"`
	HostsDenySampleLines  []string `json:"hosts_deny_sample_lines,omitempty"`
	Error                 string   `json:"error,omitempty"`
}

// LegacyInsecureServices reports presence-only hints for legacy network services.
type LegacyInsecureServices struct {
	TelnetSuspected          bool     `json:"telnet_suspected"`
	RshSuspected             bool     `json:"rsh_suspected"`
	RloginSuspected          bool     `json:"rlogin_suspected"`
	RexecSuspected           bool     `json:"rexec_suspected"`
	VsftpdSuspected          bool     `json:"vsftpd_suspected"`
	ProftpdSuspected         bool     `json:"proftpd_suspected"`
	InetdConfPresent         bool     `json:"inetd_conf_present"`
	InetdConfNonCommentLines int      `json:"inetd_conf_non_comment_lines"`
	SystemdUnitNamesSample   []string `json:"systemd_unit_names_sample,omitempty"`
	Error                    string   `json:"error,omitempty"`
}
