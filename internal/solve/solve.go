//go:build linux

// Package solve asks the service whether there is work for this machine.
//
// The agent asks; the service never calls the agent. That is the decision the
// whole channel rests on: nothing new listens on the customer's server, so
// nothing new on it can be attacked. It travels on the same outgoing HTTPS and
// the same token the agent already uses for scans.
//
// This package only carries messages. Running an action is #182's job, and
// deliberately not here — the road first, then what travels on it.
package solve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mode is what the service is asking this agent to do.
const (
	// ModeDryRun means: find out what would change, and report it. Change nothing.
	ModeDryRun = "dry_run"
	// ModeRun means: a human approved this. Do it.
	ModeRun = "run"
)

// requestTimeout is short. This runs every minute and carries almost nothing, so
// it must never be the reason the loop stalls.
const requestTimeout = 15 * time.Second

// Work is the service's answer to "is there anything for me?".
type Work struct {
	Mode    string   `json:"mode"`
	JobID   string   `json:"job_id"`
	Actions []Action `json:"actions"`

	// Backup is whether the person asked for a copy to be taken first. It is a
	// request, not an instruction: whether one is possible is measured on this
	// machine, at the moment of running.
	Backup bool `json:"backup"`
}

// Action is one thing the service is asking for: a type from the agent's own
// catalog, and the values to fill in. Never a command.
type Action struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params,omitempty"`
}

// HasWork reports whether the service gave us something to do.
//
// An empty answer is the normal case, not a failure: most machines are idle most
// of the time, and a loop that treated silence as an error would log a warning
// every minute on every quiet server.
func (w Work) HasWork() bool {
	return w.Mode == ModeDryRun || w.Mode == ModeRun
}

// DryRunReport is what would have changed, had the agent acted.
//
// Detail is whatever the runtime produced, passed through untouched: the real
// commands, their real output and the honest ledger. Summarising it here would be
// choosing for the customer what they get to see.
type DryRunReport struct {
	MachineUUID string `json:"machine_uuid"`
	JobID       string `json:"-"`
	PreviewID   string `json:"preview_id"`

	// OK is false when this machine cannot carry the actions out at all. That is
	// still a preview: the answer to "what would happen here" is "nothing, and
	// this is why". The service refuses to let such a preview be approved, so a
	// person is not sent to a server to be told a second time.
	OK bool `json:"ok"`

	Detail any `json:"detail"`
}

// ResultReport is how a run ended.
type ResultReport struct {
	MachineUUID string `json:"machine_uuid"`
	JobID       string `json:"-"`
	OK          bool   `json:"ok"`
	Detail      any    `json:"detail"`
}

// NextWork asks whether there is anything to do on this machine.
func NextWork(ctx context.Context, apiBaseURL, token, machineUUID string) (Work, error) {
	endpoint := fmt.Sprintf("%s/v1/agent/solve/work?machine_uuid=%s",
		strings.TrimRight(apiBaseURL, "/"), url.QueryEscape(machineUUID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Work{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	body, err := send(req)
	if err != nil {
		return Work{}, err
	}

	var work Work
	if err := json.Unmarshal(body, &work); err != nil {
		return Work{}, fmt.Errorf("could not read the service's answer: %w", err)
	}
	return work, nil
}

// ReportDryRun sends back what would change. The job then waits for a human.
func ReportDryRun(ctx context.Context, apiBaseURL, token string, report DryRunReport) error {
	return post(ctx, apiBaseURL, token, report.JobID, "dry-run", report)
}

// ReportResult sends back how the run ended, whether or not it worked.
func ReportResult(ctx context.Context, apiBaseURL, token string, report ResultReport) error {
	return post(ctx, apiBaseURL, token, report.JobID, "result", report)
}

func post(ctx context.Context, apiBaseURL, token, jobID, step string, payload any) error {
	if jobID == "" {
		return fmt.Errorf("cannot report a %s without saying which job it belongs to", step)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not build the %s report: %w", step, err)
	}

	endpoint := fmt.Sprintf("%s/v1/agent/solve/jobs/%s/%s",
		strings.TrimRight(apiBaseURL, "/"), url.PathEscape(jobID), step)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = send(req)
	return err
}

// send performs the request and turns anything but success into an error.
//
// A refusal is never reported as silence. A revoked token, a token bound to
// another machine, a machine the service does not know: each of those means stop
// and say so, and passing them off as "no work" would hide a broken agent for
// good — which is the whole failure this product exists to remove.
func send(req *http.Request) ([]byte, error) {
	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The service's own words are kept: they are the only thing that says
		// which rule was hit.
		return nil, fmt.Errorf("the service refused this request (%s): %s",
			resp.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, fmt.Errorf("could not read the service's answer: %w", readErr)
	}
	return body, nil
}
