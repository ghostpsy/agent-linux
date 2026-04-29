//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
		Short: "Run the first scan with a bootstrap token and store the persistent agent token.",
		Long: `register runs once per host on install. It consumes a 24h bootstrap token,
sends the first scan to the API, captures the persistent agent token returned in
the response, and writes it to /etc/ghostpsy/agent.conf (mode 0600).

Subsequent scans run with the persistent token; the bootstrap token is destroyed
on the API side after this single use.

If /etc/ghostpsy/agent.conf already exists, register refuses by default so
re-runs from automation cannot accidentally orphan a working token. Use
--force to re-register a host (e.g. after rebinding from the dashboard or
re-imaging the OS).`,
		Run: runRegisterCommand,
	}
	defaultAPI := envOr("GHOSTPSY_API_URL", "https://api.ghostpsy.com")
	cmd.Flags().String("api", defaultAPI, "API base URL")
	cmd.Flags().String("bootstrap", "", "bootstrap token (or set "+envBootstrapToken+")")
	cmd.Flags().String("save-payload", "", "write outbound payload JSON to this path before POST (dev/audit)")
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
	savePayloadPath, err := cmd.Flags().GetString("save-payload")
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
				"This host is already registered. Use `ghostpsy scan --yes` for " +
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

	st, nextSeq, _, body, err := buildScanPayload(ctx, logger)
	if err != nil {
		printErrorLine(fmt.Sprintf("register: %v", err))
		os.Exit(1)
	}

	if savePayloadPath != "" {
		if err := os.WriteFile(savePayloadPath, body, 0o600); err != nil {
			printErrorLine(fmt.Sprintf("register: write payload: %v", err))
			os.Exit(1)
		}
		logger.Note("Payload written to local file", map[string]string{"path": savePayloadPath, "payload_bytes": fmt.Sprintf("%d", len(body)), "external_send": "false"})
	}

	logger.Step("external-send",
		strings.TrimSuffix(apiURL, "/")+"/v1/ingest",
		"Sending first scan to ingest API with bootstrap token",
		map[string]string{"authorization": "Bearer bootstrap", "content_type": "application/json"})
	resp, err := postIngest(ctx, apiURL, bootstrap, body)
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

	persistent, effectiveSeq, err := parseRegisterResponse(respBody)
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

	// The API authoritatively assigns scan_seq during register so a host
	// that lost its local state (deleted state.json, OS reinstall) can
	// re-register and resume from the existing history. Honour the
	// server's value when present; fall back to the locally-computed
	// nextSeq for older API responses that lack the field.
	resolvedSeq := nextSeq
	if effectiveSeq > 0 {
		resolvedSeq = effectiveSeq
	}
	st.ScanSeq = resolvedSeq
	logger.Step("local-modifying", state.Path(),
		"Persisting scan sequence to local state",
		map[string]string{"scan_seq": fmt.Sprintf("%d", st.ScanSeq)})
	if err := state.Save(st); err != nil {
		printErrorLine(fmt.Sprintf("register: save state: %v", err))
		os.Exit(1)
	}

	printSuccessLine("Registration complete. Persistent agent token written to " + agentconfig.Path())
	printMutedLine("Next: enable scheduled scans with `ghostpsy cron install` (run as root)")
}

// parseRegisterResponse pulls the persistent token and (when present) the
// server-assigned scan_seq from the /v1/ingest response.
func parseRegisterResponse(body []byte) (string, int, error) {
	var parsed struct {
		AgentToken string `json:"agent_token"`
		ScanSeq    int    `json:"scan_seq"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("parse ingest response: %w", err)
	}
	if parsed.AgentToken == "" {
		return "", 0, errors.New("ingest response did not include agent_token (was the token a bootstrap?)")
	}
	return parsed.AgentToken, parsed.ScanSeq, nil
}
