//go:build linux

package software

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

var (
	reNginxServerTokens  = regexp.MustCompile(`(?i)server_tokens\s+([^#;]+)`)
	reApacheServerTokens = regexp.MustCompile(`(?i)ServerTokens\s+(\S+)`)
	reApacheServerSig    = regexp.MustCompile(`(?i)ServerSignature\s+(\S+)`)
	reMysqlBind          = regexp.MustCompile(`(?i)bind-address\s*=\s*(\S+)`)
	rePgListen           = regexp.MustCompile(`(?i)^\s*listen_addresses\s*=\s*([^#]+)`)
	rePgSsl              = regexp.MustCompile(`(?i)^\s*ssl\s*=\s*(\S+)`)
)

// CollectWebDbServersFingerprint reads bounded nginx/Apache/MySQL/PostgreSQL config hints.
func CollectWebDbServersFingerprint() *payload.WebDbServersFingerprint {
	out := &payload.WebDbServersFingerprint{}
	paths := []string{"/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"}
	for _, p := range paths {
		b, err := readFileBounded(p)
		if err != nil {
			continue
		}
		out.NginxConfigPathUsed = p
		if m := reNginxServerTokens.FindSubmatch(b); len(m) > 1 {
			out.NginxServerTokens = strings.TrimSpace(string(m[1]))
		}
		break
	}
	apPaths := []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/conf/httpd.conf"}
	for _, p := range apPaths {
		b, err := readFileBounded(p)
		if err != nil {
			continue
		}
		out.ApacheConfigPathUsed = p
		if m := reApacheServerTokens.FindSubmatch(b); len(m) > 1 {
			out.ApacheServerTokens = strings.TrimSpace(string(m[1]))
		}
		if m := reApacheServerSig.FindSubmatch(b); len(m) > 1 {
			out.ApacheServerSignature = strings.TrimSpace(string(m[1]))
		}
		break
	}
	mysqlPaths := []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"}
	for _, p := range mysqlPaths {
		b, err := readFileBounded(p)
		if err != nil {
			continue
		}
		if out.MysqlConfigPathUsed == "" {
			out.MysqlConfigPathUsed = p
		}
		if m := reMysqlBind.FindSubmatch(b); len(m) > 1 {
			out.MysqlBindAddress = strings.TrimSpace(string(m[1]))
			out.MysqlConfigPathUsed = p
			break
		}
	}
	// Drop-in cnf.d (first match wins)
	if out.MysqlBindAddress == "" {
		matches, _ := filepath.Glob("/etc/mysql/conf.d/*.cnf")
		for _, p := range matches {
			b, err := readFileBounded(p)
			if err != nil {
				continue
			}
			if m := reMysqlBind.FindSubmatch(b); len(m) > 1 {
				out.MysqlConfigPathUsed = p
				out.MysqlBindAddress = strings.TrimSpace(string(m[1]))
				break
			}
		}
	}
	pgGlobs := []string{"/etc/postgresql/*/main/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf", "/var/lib/postgres/data/postgresql.conf"}
	for _, g := range pgGlobs {
		matches, _ := filepath.Glob(g)
		for _, p := range matches {
			b, err := readFileBounded(p)
			if err != nil {
				continue
			}
			var listen, ssl string
			for _, line := range strings.Split(string(b), "\n") {
				if m := rePgListen.FindStringSubmatch(line); len(m) > 1 {
					listen = strings.TrimSpace(strings.Trim(m[1], `"'`))
				}
				if m := rePgSsl.FindStringSubmatch(line); len(m) > 1 {
					ssl = strings.TrimSpace(strings.Trim(m[1], `"'`))
				}
			}
			if listen != "" || ssl != "" {
				out.PostgresqlConfigPathUsed = p
				out.PostgresqlListenAddresses = listen
				out.PostgresqlSsl = ssl
				return out
			}
		}
	}
	return out
}
