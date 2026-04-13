//go:build linux

package postgres

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
)

const postgresPsTimeout = 4 * time.Second

func filePermissionSummary(path string) *string {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	mode := fi.Mode().Perm() & 0o777
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		s := fmt.Sprintf("%04o", mode)
		return &s
	}
	s := fmt.Sprintf("%04o uid=%d gid=%d", mode, st.Uid, st.Gid)
	return &s
}

func postgresRunUser(ctx context.Context) *string {
	subCtx, cancel := context.WithTimeout(ctx, postgresPsTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, "ps", "axo", "user,comm")
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) == 0 {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		comm := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.Contains(comm, "postgres") || strings.Contains(comm, "postmaster") {
			u := shared.TruncateRunes(user, 64)
			return &u
		}
	}
	return nil
}

func evalSslMinProtocolWeak(val *string) *bool {
	if val == nil || strings.TrimSpace(*val) == "" {
		return shared.BoolPtr(true)
	}
	u := strings.ToUpper(strings.TrimSpace(*val))
	if strings.Contains(u, "TLSV1.3") || strings.Contains(u, "TLSV1.2") {
		return shared.BoolPtr(false)
	}
	if strings.Contains(u, "TLSV1.1") || strings.Contains(u, "TLSV1.0") || strings.Contains(u, "SSLV3") || strings.Contains(u, "SSLV2") {
		return shared.BoolPtr(true)
	}
	if u == "TLSV1" || strings.HasPrefix(u, "TLSV1 ") {
		return shared.BoolPtr(true)
	}
	return shared.BoolPtr(false)
}

func evalSslCiphersWeak(val *string) *bool {
	if val == nil || strings.TrimSpace(*val) == "" {
		return nil
	}
	if reWeakCipherToken.MatchString(*val) {
		return shared.BoolPtr(true)
	}
	return shared.BoolPtr(false)
}

func evalPasswordEncryptionWeakMd5(val *string) *bool {
	if val == nil {
		return nil
	}
	if strings.TrimSpace(*val) == "" {
		return nil
	}
	low := strings.ToLower(strings.TrimSpace(*val))
	if strings.Contains(low, "md5") {
		return shared.BoolPtr(true)
	}
	return shared.BoolPtr(false)
}

func evalPreloadAuditTrail(lib *string) *bool {
	if lib == nil || strings.TrimSpace(*lib) == "" {
		return shared.BoolPtr(false)
	}
	low := strings.ToLower(*lib)
	ok := strings.Contains(low, "pg_stat_statements") || strings.Contains(low, "pgaudit")
	return &ok
}
