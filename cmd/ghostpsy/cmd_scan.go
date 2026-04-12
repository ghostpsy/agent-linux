//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/state"
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Build payload, print JSON for review, optionally POST to API",
		Long: `Register this host if needed, build the allowlisted payload, print JSON for review,
and optionally POST to the API after confirmation.

Scan options honor GHOSTPSY_API_URL unless --api is set.`,
		Run: runScanCommand,
	}
	defaultAPI := envOr("GHOSTPSY_API_URL", "https://api.ghostpsy.com")
	cmd.Flags().String("api", defaultAPI, "API base URL")
	cmd.Flags().Bool("dry-run", false, "only print payload, do not POST")
	cmd.Flags().String("save-payload", "", "write outbound payload JSON to this path before optional POST")
	cmd.Flags().Bool("verbose", false, "print action-by-action runtime logs with safety summary")
	return cmd
}

func runScanCommand(cmd *cobra.Command, _ []string) {
	apiURL, err := cmd.Flags().GetString("api")
	if err != nil {
		printErrorLine("scan: invalid flags")
		os.Exit(1)
	}
	dry, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		printErrorLine("scan: invalid flags")
		os.Exit(1)
	}
	savePayloadPath, err := cmd.Flags().GetString("save-payload")
	if err != nil {
		printErrorLine("scan: invalid flags")
		os.Exit(1)
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		printErrorLine("scan: invalid flags")
		os.Exit(1)
	}

	logger := actionlog.New(verbose, os.Stdout)
	defer logger.PrintSummary()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, nextSeq, p, body, err := buildScanPayload(ctx, logger)
	if err != nil {
		printErrorLine(fmt.Sprintf("scan: %v", err))
		os.Exit(1)
	}

	printSectionTitle(os.Stdout, "--- Outbound payload (review before any send) ---")
	if err := writePayloadPreview(os.Stdout, p); err != nil {
		printErrorLine(fmt.Sprintf("scan: preview payload: %v", err))
		os.Exit(1)
	}
	printSectionTitle(os.Stdout, "--- End payload ---")
	if savePayloadPath != "" {
		if err := os.WriteFile(savePayloadPath, body, 0o600); err != nil {
			printErrorLine(fmt.Sprintf("write payload: %v", err))
			os.Exit(1)
		}
		logger.Note("Payload written to local file", map[string]string{"path": savePayloadPath, "payload_bytes": fmt.Sprintf("%d", len(body)), "external_send": "false"})
		printSuccessLine("Saved outbound payload to: " + savePayloadPath)
	}

	if dry {
		logger.Note("Dry-run enabled: payload is NOT sent to the API", map[string]string{"external_send": "false"})
		printMutedLine("(dry-run: not sending; scan_seq unchanged on disk)")
		return
	}

	fmt.Print("Send this payload to API? [y/N]: ")
	line, err := readConfirmLine()
	if err != nil {
		printErrorLine(fmt.Sprintf("read confirm: %v", err))
		os.Exit(1)
	}
	if strings.TrimSpace(strings.ToLower(line)) != "y" {
		fmt.Println("Aborted.")
		os.Exit(0)
	}

	token := os.Getenv("GHOSTPSY_INGEST_TOKEN")
	if token == "" {
		printErrorLine("GHOSTPSY_INGEST_TOKEN is not set")
		os.Exit(1)
	}

	logger.Step("external-send", strings.TrimSuffix(apiURL, "/")+"/v1/ingest", "Sending allowlisted payload to the ingest API endpoint", map[string]string{"authorization": "Bearer token", "content_type": "application/json"})
	resp, err := postIngest(ctx, apiURL, token, body)
	if err != nil {
		printErrorLine(fmt.Sprintf("post: %v", err))
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := readLimited(resp.Body, maxIngestResponseBodyBytes)
	if err != nil {
		printErrorLine(fmt.Sprintf("read response body: %v", err))
		os.Exit(1)
	}
	fmt.Println("Response:", resp.Status, string(respBody))
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
	st.ScanSeq = nextSeq
	logger.Step("local-modifying", "~/.config/ghostpsy/agent.json", "Persisting updated scan sequence to local state file", map[string]string{"scan_seq": fmt.Sprintf("%d", st.ScanSeq)})
	if err := state.Save(st); err != nil {
		printErrorLine(fmt.Sprintf("save state: %v", err))
		os.Exit(1)
	}
}
