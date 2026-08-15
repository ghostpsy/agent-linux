//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// heartbeatBody is what the agent tells the service every fifteen minutes.
//
// SudoRuleCurrent is a pointer because absent and false are different answers.
// An agent that could not check must say nothing rather than claim the rule is
// fine — the service records "we do not know" separately from "it drifted".
type heartbeatBody struct {
	MachineUUID     string `json:"machine_uuid"`
	AgentVersion    string `json:"agent_version,omitempty"`
	SudoRuleCurrent *bool  `json:"sudo_rule_current,omitempty"`
}

// heartbeatTimeout is short on purpose. This request runs every fifteen
// minutes and carries nothing important; it must never hold the loop up.
const heartbeatTimeout = 10 * time.Second

func postHeartbeat(ctx context.Context, apiBaseURL, token string, body heartbeatBody) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("could not build the heartbeat: %w", err)
	}

	url := strings.TrimRight(apiBaseURL, "/") + "/v1/agent/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: heartbeatTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the service refused the heartbeat (%s)", resp.Status)
	}
	return nil
}
