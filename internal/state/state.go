// Package state persists the bits of agent identity that have to survive
// across runs: the machine UUID (when /etc/machine-id is unavailable) and
// the monotonic scan sequence counter.
//
// The token credential is NOT here; it lives at /etc/ghostpsy/agent.conf
// (see internal/agentconfig). State is read/written by every scan and is
// kept under /var/lib/ghostpsy/ because the agent runs as root via cron
// or systemd; per-user XDG locations would land in /root/.config which is
// not a sensible home for system-service state.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// envPathOverride lets tests redirect the state file. Production code
// always writes to /var/lib/ghostpsy/state.json.
const envPathOverride = "GHOSTPSY_STATE_PATH"

const defaultPath = "/var/lib/ghostpsy/state.json"
const dirMode os.FileMode = 0o755
const fileMode os.FileMode = 0o600

// AgentState is persisted after the first successful scan: a stable
// machine identity and the scan_seq counter.
type AgentState struct {
	MachineUUID string `json:"machine_uuid"`
	ScanSeq     int    `json:"scan_seq"`
}

// Path returns the resolved state-file path.
func Path() string {
	if v := strings.TrimSpace(os.Getenv(envPathOverride)); v != "" {
		return v
	}
	return defaultPath
}

// Load reads the state file. Returns an error when the file is missing,
// malformed, or has no machine UUID.
func Load() (*AgentState, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		return nil, err
	}
	var s AgentState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.MachineUUID == "" {
		return nil, errors.New("invalid state: missing machine_uuid")
	}
	return &s, nil
}

// Save writes the state file with mode 0600 owner=root and creates the
// containing directory if missing.
func Save(s *AgentState) error {
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), dirMode); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, fileMode)
}
