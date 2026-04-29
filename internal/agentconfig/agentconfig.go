// Package agentconfig stores the persistent agent token at /etc/ghostpsy/agent.conf.
//
// The file holds a single line: the raw bearer token. Permissions are
// enforced to 0600 owner=root so a non-privileged user on the host cannot
// read the credential. Tests override the path via GHOSTPSY_AGENT_CONFIG_PATH.
package agentconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// envPathOverride lets tests redirect the config file. Production code
// always writes to /etc/ghostpsy/agent.conf.
const envPathOverride = "GHOSTPSY_AGENT_CONFIG_PATH"

const defaultPath = "/etc/ghostpsy/agent.conf"

// requiredFileMode is the permission bits Load expects on the config file.
// Anything looser (group- or world-readable) is treated as a misconfiguration
// and refused so the credential never escapes via a shared host account.
const requiredFileMode os.FileMode = 0o600

// dirMode is applied to the parent directory at Save time when missing.
const dirMode os.FileMode = 0o755

// ErrNotConfigured signals that no persistent token exists yet (the agent
// has not been registered on this host).
var ErrNotConfigured = errors.New("agent not registered: agent.conf is missing")

// Path returns the resolved configuration file path.
func Path() string {
	if v := strings.TrimSpace(os.Getenv(envPathOverride)); v != "" {
		return v
	}
	return defaultPath
}

// Exists reports whether the persistent agent token file is already on disk.
//
// Used by ``register`` to refuse re-runs (with a clear error) and by
// idempotent install scripts to decide between ``register`` and a plain
// ``scan --yes``. Permission errors fall through as "does not exist" so
// callers see a single source of truth: the file is treated as
// already-configured when it is readable; anything else means register
// should attempt to write it.
func Exists() bool {
	_, err := os.Stat(Path())
	return err == nil
}

// Load reads the persistent agent token.
//
// Returns ErrNotConfigured if the file does not exist. Refuses to read if
// the file mode is looser than 0600 (the caller should then re-register
// rather than continue with an exposed credential).
func Load() (string, error) {
	p := Path()
	info, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotConfigured
		}
		return "", fmt.Errorf("stat %s: %w", p, err)
	}
	if mode := info.Mode().Perm(); mode != requiredFileMode {
		return "", fmt.Errorf(
			"refusing to read %s with permissions %#o; expected %#o (run: chmod %#o %s)",
			p, mode, requiredFileMode, requiredFileMode, p,
		)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", p, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("agent.conf is empty: %s", p)
	}
	return token, nil
}

// Save writes the persistent agent token with mode 0600.
//
// The parent directory is created if missing. The file is written via a
// temp file + rename so a concurrent reader never sees a half-written
// credential.
func Save(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("token must not be empty")
	}
	p := Path()
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".agent.conf.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(requiredFileMode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, p); err != nil {
		cleanup()
		return fmt.Errorf("rename to %s: %w", p, err)
	}
	return nil
}
