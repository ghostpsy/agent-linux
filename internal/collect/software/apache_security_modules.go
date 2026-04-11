//go:build linux

package software

import "strings"

// apacheSecurityRelevantModuleNames lists LoadModule logical names that materially affect attack surface
// or common hardening controls (WAF, timeouts, TLS, proxy/CGI/LDAP/WebDAV, info leakage). Not exhaustive of
// every distro spelling; extend when a real module name is missing.
var apacheSecurityRelevantModuleNames = map[string]struct{}{
	"authnz_ldap_module":    {},
	"auth_openidc_module":   {},
	"cgid_module":           {},
	"cgi_module":            {},
	"dav_fs_module":         {},
	"dav_lock_module":       {},
	"dav_module":            {},
	"evasive24_module":      {},
	"evasive_module":        {},
	"fcgid_module":          {},
	"http2_module":          {},
	"info_module":           {},
	"ldap_module":           {},
	"perl_module":           {},
	"proxy_ajp_module":      {},
	"proxy_balancer_module": {},
	"proxy_connect_module":  {},
	"proxy_fcgi_module":     {},
	"proxy_fdp_module":      {},
	"proxy_http_module":     {},
	"proxy_module":          {},
	"proxy_wstunnel_module": {},
	"reqtimeout_module":     {},
	"security2_module":      {},
	"ssl_module":            {},
	"status_module":         {},
	"userdir_module":        {},
	"wsgi_module":           {},
}

func isSecurityRelevantApacheModule(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := apacheSecurityRelevantModuleNames[name]; ok {
		return true
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, "_module") {
		return true
	}
	return false
}
