package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// AgentState is persisted after the first successful `scan` setup (machine identity on this host).
type AgentState struct {
	MachineUUID string `json:"machine_uuid"`
	ClaimCode   string `json:"claim_code"`
	ScanSeq     int    `json:"scan_seq"`
}

func path() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".config", "ghostpsy", "agent.json"), nil
}

// Load reads ~/.config/ghostpsy/agent.json
func Load() (*AgentState, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
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

// Save writes state (creates directory).
func Save(s *AgentState) error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}
