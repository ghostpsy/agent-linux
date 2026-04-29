//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/agentconfig"
	"github.com/ghostpsy/agent-linux/internal/state"
)

const (
	envBootstrapToken = "GHOSTPSY_BOOTSTRAP_TOKEN"
)

func newRegisterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Exchange a bootstrap token for a long-lived agent token (no scan).",
		Long: `register runs once per host on install. It consumes a 24h bootstrap
token, mints a persistent agent token bound to this machine, and writes
it to /etc/ghostpsy/agent.conf (mode 0600). It does NOT send a scan —
run ` + "`sudo ghostpsy scan`" + ` afterwards (you can review the JSON
payload before confirming).

If /etc/ghostpsy/agent.conf already exists, register refuses by default
so re-runs from automation cannot accidentally orphan a working token.
Use --force to re-register a host (e.g. after re-imaging the OS or after
losing the local state file). On re-register the API revokes any other
active agent tokens for this machine and resumes the scan_seq counter,
so the existing scan history is preserved.`,
		Run: runRegisterCommand,
	}
	defaultAPI := envOr("GHOSTPSY_API_URL", "https://api.ghostpsy.com")
	cmd.Flags().String("api", defaultAPI, "API base URL")
	cmd.Flags().String("bootstrap", "", "bootstrap token (or set "+envBootstrapToken+")")
	cmd.Flags().Bool("verbose", false, "print action-by-action runtime logs with safety summary")
	cmd.Flags().Bool("force", false, "re-register even if /etc/ghostpsy/agent.conf already exists")
	return cmd
}

func runRegisterCommand(cmd *cobra.Command, _ []string) {
	apiURL, err := cmd.Flags().GetString("api")
	if err != nil {
		printErrorLine("register: invalid flags")
		os.Exit(1)
	}
	bootstrapFlag, err := cmd.Flags().GetString("bootstrap")
	if err != nil {
		printErrorLine("register: invalid flags")
		os.Exit(1)
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		printErrorLine("register: invalid flags")
		os.Exit(1)
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		printErrorLine("register: invalid flags")
		os.Exit(1)
	}

	if !force && agentconfig.Exists() {
		printErrorLine(
			"register: " + agentconfig.Path() + " already exists. " +
				"This host is already registered. Use `ghostpsy scan` for " +
				"subsequent scans, or pass --force to re-register.",
		)
		os.Exit(1)
	}

	bootstrap := strings.TrimSpace(bootstrapFlag)
	if bootstrap == "" {
		bootstrap = strings.TrimSpace(os.Getenv(envBootstrapToken))
	}
	if bootstrap == "" {
		printErrorLine("register: bootstrap token required (--bootstrap=<token> or " + envBootstrapToken + ")")
		os.Exit(1)
	}

	logger := actionlog.New(verbose, os.Stdout)
	defer logger.PrintSummary()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Step("local-read-only", state.Path(),
		"Reading or seeding local agent identity at "+state.Path(), nil)
	st := ensureState(logger)

	logger.Step("external-send",
		strings.TrimSuffix(apiURL, "/")+"/v1/agent/register",
		"Exchanging bootstrap for persistent agent token (no scan)",
		map[string]string{"authorization": "Bearer bootstrap", "content_type": "application/json"})
	resp, err := postRegister(ctx, apiURL, bootstrap, st.MachineUUID)
	if err != nil {
		printErrorLine(fmt.Sprintf("register: post: %v", err))
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := readLimited(resp.Body, maxIngestResponseBodyBytes)
	if err != nil {
		printErrorLine(fmt.Sprintf("register: read response: %v", err))
		os.Exit(1)
	}
	if resp.StatusCode >= 400 {
		fmt.Println("Response:", resp.Status, string(respBody))
		os.Exit(1)
	}

	persistent, lastScanSeq, err := parseRegisterResponse(respBody)
	if err != nil {
		printErrorLine(fmt.Sprintf("register: %v", err))
		os.Exit(1)
	}

	logger.Step("local-modifying", agentconfig.Path(),
		"Writing persistent agent token to "+agentconfig.Path()+" (mode 0600)", nil)
	if err := agentconfig.Save(persistent); err != nil {
		printErrorLine(fmt.Sprintf("register: save token: %v", err))
		os.Exit(1)
	}

	// The API tells us the highest scan_seq it currently holds for this
	// machine (zero on a fresh machine, max-of-existing on re-register).
	// Persist it as the "last used" counter — the next `scan` increments
	// from there and stays in lockstep with the API's history.
	st.ScanSeq = lastScanSeq
	logger.Step("local-modifying", state.Path(),
		"Persisting scan sequence to local state",
		map[string]string{"scan_seq": fmt.Sprintf("%d", st.ScanSeq)})
	if err := state.Save(st); err != nil {
		printErrorLine(fmt.Sprintf("register: save state: %v", err))
		os.Exit(1)
	}

	printSuccessLine("Registration complete. Persistent agent token written to " + agentconfig.Path())
	printMutedLine("Next: run `sudo ghostpsy scan` to send the first scan (you can review the JSON before it leaves the host).")
	printMutedLine("Schedule recurring scans with `sudo ghostpsy cron install`.")
}

// postRegister POSTs the bootstrap-token register body to the API.
func postRegister(ctx context.Context, apiBaseURL, bootstrap, machineUUID string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	url := strings.TrimSuffix(apiBaseURL, "/") + "/v1/agent/register"
	body, err := json.Marshal(map[string]string{"machine_uuid": machineUUID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bootstrap)
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// parseRegisterResponse pulls the persistent token and the last-used
// scan_seq from the /v1/agent/register response.
func parseRegisterResponse(body []byte) (string, int, error) {
	var parsed struct {
		AgentToken string `json:"agent_token"`
		ScanSeq    int    `json:"scan_seq"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("parse register response: %w", err)
	}
	if parsed.AgentToken == "" {
		return "", 0, errors.New("register response did not include agent_token")
	}
	return parsed.AgentToken, parsed.ScanSeq, nil
}
