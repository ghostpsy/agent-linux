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

	"ghostpsy/agent-linux/internal/collect"
	"ghostpsy/agent-linux/internal/state"
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

Environment:
  GHOSTPSY_API_URL   Base URL for ingest (default https://localhost:8000)
  GHOSTPSY_INGEST_TOKEN   Bearer token issued after claim bind (required to send)

`)
}

func ensureState() *state.AgentState {
	st, err := state.Load()
	if err == nil {
		return st
	}
	mid := uuid.NewString()
	claim := strings.ToUpper(uuid.NewString()[:8])
	s := &state.AgentState{
		MachineUUID: mid,
		ClaimCode:   claim,
		ScanSeq:     0,
	}
	if err := state.Save(s); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("First run: registered this host.")
	fmt.Println("Machine UUID:", mid)
	fmt.Println("Claim code (paste in dashboard while logged in):", claim)
	fmt.Println("State file: ~/.config/ghostpsy/agent.json")
	return s
}

func runScan() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	apiURL := fs.String("api", envOr("GHOSTPSY_API_URL", "http://127.0.0.1:8000"), "API base URL")
	dry := fs.Bool("dry-run", false, "only print payload, do not POST")
	_ = fs.Parse(os.Args[2:])

	st := ensureState()
	nextSeq := st.ScanSeq + 1
	p := collect.Stub(st.MachineUUID, nextSeq)
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("--- Outbound payload (review before any send) ---")
	fmt.Println(string(body))
	fmt.Println("--- End payload ---")

	if *dry {
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
	if err := state.Save(st); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
		os.Exit(1)
	}
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
