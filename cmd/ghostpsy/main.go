//go:build linux

// ghostpsy collects allowlisted server metadata and sends it after operator preview.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/collect"
	"github.com/ghostpsy/agent-linux/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		runScan()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ghostpsy — legacy server telemetry (allowlisted)

Commands:
  scan       Register this host if needed, build payload, print JSON for review, optionally POST to API.

Scan options:
  --verbose  Print action-by-action runtime logs and a safety summary.
  --dry-run  Build and print payload only (never POST).
  --save-payload <path>  Save the exact outbound JSON payload to a local file before optional POST.

Environment:
  GHOSTPSY_API_URL   Base URL for ingest (default https://localhost:8000)
  GHOSTPSY_INGEST_TOKEN   Bearer token issued after claim bind (required to send)

`)
}

func ensureState(logger *actionlog.Logger) *state.AgentState {
	st, err := state.Load()
	if err == nil {
		return st
	}
	mid := uuid.NewString()
	midSource := "random"
	if osMid, ok := state.MachineUUIDFromOS(); ok {
		mid = osMid
		midSource = "OS machine-id (/etc/machine-id or /var/lib/dbus/machine-id)"
	}
	claim := strings.ToUpper(uuid.NewString()[:8])
	s := &state.AgentState{
		MachineUUID: mid,
		ClaimCode:   claim,
		ScanSeq:     0,
	}
	logger.Step("local-modifying", "~/.config/ghostpsy/agent.json", "Initializing local agent identity file in ~/.config/ghostpsy/agent.json", nil)
	if err := state.Save(s); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("First run: registered this host.")
	fmt.Println("Machine UUID:", mid, "("+midSource+")")
	fmt.Println("Claim code (paste in dashboard while logged in):", claim)
	fmt.Println("State file: ~/.config/ghostpsy/agent.json")
	return s
}

func runScan() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	apiURL := fs.String("api", envOr("GHOSTPSY_API_URL", "http://127.0.0.1:8000"), "API base URL")
	dry := fs.Bool("dry-run", false, "only print payload, do not POST")
	savePayloadPath := fs.String("save-payload", "", "write outbound payload JSON to this path before optional POST")
	verbose := fs.Bool("verbose", false, "print action-by-action runtime logs with safety summary")
	_ = fs.Parse(os.Args[2:])
	logger := actionlog.New(*verbose, os.Stdout)
	defer logger.PrintSummary()

	st, nextSeq, body := buildScanPayload(logger)

	fmt.Println("--- Outbound payload (review before any send) ---")
	fmt.Println(string(body))
	fmt.Println("--- End payload ---")
	if *savePayloadPath != "" {
		if err := os.WriteFile(*savePayloadPath, body, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write payload: %v\n", err)
			os.Exit(1)
		}
		logger.Note("Payload written to local file", map[string]string{"path": *savePayloadPath, "payload_bytes": fmt.Sprintf("%d", len(body)), "external_send": "false"})
		fmt.Println("Saved outbound payload to:", *savePayloadPath)
	}

	if *dry {
		logger.Note("Dry-run enabled: payload is NOT sent to the API", map[string]string{"external_send": "false"})
		fmt.Println("(dry-run: not sending; scan_seq unchanged on disk)")
		return
	}

	fmt.Print("Send this payload to API? [y/N]: ")
	var line string
	_, _ = fmt.Scanln(&line)
	if strings.TrimSpace(strings.ToLower(line)) != "y" {
		fmt.Println("Aborted.")
		os.Exit(0)
	}

	token := os.Getenv("GHOSTPSY_INGEST_TOKEN")
	if token == "" {
		fmt.Fprintf(os.Stderr, "GHOSTPSY_INGEST_TOKEN is not set\n")
		os.Exit(1)
	}

	logger.Step("external-send", strings.TrimSuffix(*apiURL, "/")+"/v1/ingest", "Sending allowlisted payload to the ingest API endpoint", map[string]string{"authorization": "Bearer token", "content_type": "application/json"})
	resp, err := postIngest(*apiURL, token, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "post: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("Response:", resp.Status, string(respBody))
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
	st.ScanSeq = nextSeq
	logger.Step("local-modifying", "~/.config/ghostpsy/agent.json", "Persisting updated scan sequence to local state file", map[string]string{"scan_seq": fmt.Sprintf("%d", st.ScanSeq)})
	if err := state.Save(st); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
		os.Exit(1)
	}
}

func buildScanPayload(logger *actionlog.Logger) (*state.AgentState, int, []byte) {
	logger.Step("local-read-only", "~/.config/ghostpsy/agent.json", "Reading local agent state from ~/.config/ghostpsy/agent.json", nil)
	st := ensureState(logger)
	nextSeq := st.ScanSeq + 1
	logger.Step("local-compute", "payload.v1", "Building allowlisted inventory payload from local system data", map[string]string{"scan_seq": fmt.Sprintf("%d", nextSeq)})
	p := collect.StubWithObserver(st.MachineUUID, nextSeq, func(event collect.ActionEvent) {
		if event.Phase == "start" {
			logger.Step("local-read-only", event.Action, humanMessageForCollectionAction(event.Action), nil)
			return
		}
		if event.Error != "" {
			logger.Note(humanDoneWarningMessage(event.Action, event.Items, event.Error), nil)
			return
		}
		logger.Note(humanDoneMessage(event.Action, event.Items), nil)
	})
	logger.Step("local-compute", "payload.v1", "Preparing JSON payload preview before any network send", nil)
	body, err := json.MarshalIndent(p, "", "  ")
	if err == nil {
		logger.Note("Payload prepared successfully", map[string]string{"payload_bytes": fmt.Sprintf("%d", len(body))})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	return st, nextSeq, body
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// postIngest POSTs JSON to {apiBaseURL}/v1/ingest with a Bearer token.
func postIngest(apiBaseURL, token string, body []byte) (*http.Response, error) {
	url := strings.TrimSuffix(apiBaseURL, "/") + "/v1/ingest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 60 * time.Second}
	return client.Do(req)
}

func humanMessageForCollectionAction(action string) string {
	switch action {
	case "collect_host_network":
		return "Extracting network interfaces and public IP candidates from local network stack"
	case "collect_host_disk":
		return "Extracting mount points and disk usage from local filesystem metadata"
	case "collect_host_users_summary":
		return "Extracting user names, shell, UID and GID from /etc/passwd"
	case "collect_host_ssh":
		return "Extracting OpenSSH hardening settings from sshd configuration files"
	case "collect_packages_updates":
		return "Extracting available package updates from the system package manager"
	case "collect_host_backup":
		return "Extracting backup schedule and status from local backup configuration"
	case "collect_services":
		return "Extracting enabled/active service states from systemd and init services"
	case "collect_os_info":
		return "Extracting operating system name, version and kernel information"
	case "collect_firewall":
		return "Extracting firewall rules and default policies from nftables/iptables"
	case "collect_host_path":
		return "Extracting PATH directory entries and world-writable flags"
	case "collect_host_suid":
		return "Extracting a capped setuid binary inventory from standard locations"
	case "collect_host_process":
		return "Extracting top CPU and memory processes plus interpreter counts"
	case "collect_host_runtimes":
		return "Detecting installed language runtimes on PATH"
	case "collect_listeners":
		return "Extracting listening ports and processes from local socket tables"
	default:
		return "Extracting allowlisted local system data"
	}
}

func humanDoneMessage(action string, items int) string {
	switch action {
	case "collect_host_users_summary":
		return fmt.Sprintf("Done: extracted %d user entries from /etc/passwd.", items)
	case "collect_host_disk":
		return fmt.Sprintf("Done: extracted %d filesystem usage entries.", items)
	case "collect_host_network":
		return fmt.Sprintf("Done: extracted %d network interface entries.", items)
	case "collect_services":
		return fmt.Sprintf("Done: extracted %d service entries.", items)
	case "collect_packages_updates":
		return fmt.Sprintf("Done: found %d pending package updates.", items)
	case "collect_host_ssh":
		return fmt.Sprintf("Done: extracted %d SSH listen address entries.", items)
	case "collect_listeners":
		return fmt.Sprintf("Done: extracted %d listening port entries.", items)
	case "collect_firewall":
		return fmt.Sprintf("Done: extracted %d firewall rule metrics.", items)
	case "collect_host_path":
		return fmt.Sprintf("Done: extracted %d PATH directory entries.", items)
	case "collect_host_suid":
		return fmt.Sprintf("Done: extracted %d setuid file entries.", items)
	case "collect_host_process":
		return fmt.Sprintf("Done: extracted %d top process entries.", items)
	case "collect_host_runtimes":
		return fmt.Sprintf("Done: detected %d language runtimes.", items)
	case "collect_host_backup":
		if items == 0 {
			return "Done: no backup tool detected on this host."
		}
		return fmt.Sprintf("Done: detected %d backup tools.", items)
	case "collect_os_info":
		return "Done: extracted operating system and kernel information."
	default:
		return fmt.Sprintf("Done: extracted %d entries.", items)
	}
}

func humanDoneWarningMessage(action string, items int, errText string) string {
	switch action {
	case "collect_host_backup":
		return fmt.Sprintf("Done with warning: no backup evidence detected (%s).", errText)
	default:
		return fmt.Sprintf("Done with warning: extracted %d entries, but encountered an issue (%s).", items, errText)
	}
}
