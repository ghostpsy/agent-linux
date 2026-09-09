//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/release"
	"github.com/ghostpsy/agent-linux/internal/version"
)

const (
	envBinPathOverride = "GHOSTPSY_BIN_PATH"
	defaultBinPath     = "/usr/local/bin/ghostpsy"
	previousSuffix     = ".previous"
	maxArtifactBytes   = 100 << 20 // 100 MiB cap on any downloaded file.
)

// updateCheckResponse is the payload returned by GET /v1/agent/update-check.
type updateCheckResponse struct {
	LatestVersion       string `json:"latest_version"`
	MinSupportedVersion string `json:"min_supported_version"`
	DownloadURL         string `json:"download_url"`
	Sha256SumsURL       string `json:"sha256sums_url"`
	SignatureURL        string `json:"signature_url"`
	BinaryFilename      string `json:"binary_filename"`
}

func newUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for a new agent release and install it (signed binaries only).",
		Long: `update queries the Ghostpsy API for the latest released agent. With
` + "`--check`" + ` it only reports the latest version vs the running version.
Without ` + "`--check`" + ` it downloads the binary, verifies the Ed25519 signature
on SHA256SUMS, verifies the binary hash, and atomically swaps
/usr/local/bin/ghostpsy. The replaced binary is kept as /usr/local/bin/ghostpsy.previous
for rollback.

This command never auto-execs the new binary — the next scheduled or manual
` + "`scan`" + ` picks it up.`,
		Run: runUpdateCommand,
	}
	defaultAPI := envOr("GHOSTPSY_API_URL", "https://api.ghostpsy.com")
	cmd.Flags().String("api", defaultAPI, "API base URL")
	cmd.Flags().Bool("check", false, "only report whether an update is available; do not install")
	return cmd
}

func runUpdateCommand(cmd *cobra.Command, _ []string) {
	apiURL, err := cmd.Flags().GetString("api")
	if err != nil {
		printErrorLine("update: invalid flags")
		os.Exit(1)
	}
	checkOnly, err := cmd.Flags().GetBool("check")
	if err != nil {
		printErrorLine("update: invalid flags")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	info, err := fetchUpdateCheck(ctx, apiURL, version.DisplayGOARCH())
	if err != nil {
		printErrorLine(fmt.Sprintf("update: %v", err))
		os.Exit(1)
	}

	current := version.Version
	fmt.Printf("Current version: %s\n", current)
	fmt.Printf("Latest version:  %s\n", info.LatestVersion)
	if info.MinSupportedVersion != "" {
		fmt.Printf("Minimum supported: %s\n", info.MinSupportedVersion)
	}

	if current == info.LatestVersion {
		printSuccessLine("Already on the latest version.")
		return
	}
	if !versionLess(current, info.LatestVersion) {
		// Local binary is newer than the published release — usually a dev build
		// or a release that has not finished publishing yet. Don't pretend we're
		// on "the latest"; a dev binary is not what end-users should run.
		printMutedLine(fmt.Sprintf(
			"This binary is newer than the latest published release (%s). No update available.",
			info.LatestVersion,
		))
		return
	}
	if checkOnly {
		printMutedLine("Run `ghostpsy update` (without --check) to install.")
		return
	}

	if err := installUpdate(ctx, info); err != nil {
		printErrorLine(fmt.Sprintf("update: %v", err))
		os.Exit(1)
	}
	printSuccessLine("Updated to version " + info.LatestVersion + ". Next scan will use the new binary.")
}

// fetchUpdateCheck calls GET /v1/agent/update-check?arch=<arch>.
func fetchUpdateCheck(ctx context.Context, apiBase, arch string) (*updateCheckResponse, error) {
	u := strings.TrimSuffix(apiBase, "/") + "/v1/agent/update-check?arch=" + arch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update-check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("update-check returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes))
	if err != nil {
		return nil, fmt.Errorf("update-check read: %w", err)
	}
	out := &updateCheckResponse{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("update-check parse: %w", err)
	}
	if out.LatestVersion == "" || out.DownloadURL == "" {
		return nil, errors.New("update-check response missing latest_version or download_url")
	}
	return out, nil
}

// installUpdate downloads, verifies, and atomically swaps the binary.
func installUpdate(ctx context.Context, info *updateCheckResponse) error {
	return installUpdateWithGrant(ctx, info, installedGrantPath, runCommand)
}

// installUpdateWithGrant is installUpdate with the sudo grant path and the
// command runner taken as parameters, test-only: it lets a test point the
// refresh at a throwaway file and a fake runner instead of the real,
// root-owned /etc/sudoers.d/ghostpsy and a real invocation of visudo.
// installUpdate is the only production caller, and it always pins both to the
// real thing.
func installUpdateWithGrant(ctx context.Context, info *updateCheckResponse, grantPath string, run runner) error {
	sumsContent, err := downloadBytes(ctx, info.Sha256SumsURL)
	if err != nil {
		return fmt.Errorf("download SHA256SUMS: %w", err)
	}
	sigContent, err := downloadBytes(ctx, info.SignatureURL)
	if err != nil {
		return fmt.Errorf("download SHA256SUMS.sig: %w", err)
	}
	if err := release.VerifyShaSums(sumsContent, string(sigContent)); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	binaryContent, err := downloadBytes(ctx, info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	filename := info.BinaryFilename
	if filename == "" {
		filename = filepath.Base(info.DownloadURL)
	}
	if err := release.VerifyBinaryHash(sumsContent, filename, binaryContent); err != nil {
		return fmt.Errorf("verify hash: %w", err)
	}
	if err := atomicSwap(binaryContent); err != nil {
		return err
	}

	// The new binary may allow commands the installed grant does not. Refused
	// deliberately loudly: an agent whose grant is a version behind fails one
	// action at a time, on a customer's server, with "a password is required" —
	// which reads like a broken machine rather than a half-finished update.
	if err := refreshSudoRule(grantPath, run); err != nil {
		return fmt.Errorf("the agent was updated but its sudo rule was not: %w", err)
	}
	return nil
}

func downloadBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes))
}

// atomicSwap writes the new binary to a temp file in the same directory,
// fsyncs, then renames it over the install path. The previous binary is
// kept at install_path.previous for rollback.
func atomicSwap(newBinary []byte) error {
	binPath := strings.TrimSpace(os.Getenv(envBinPathOverride))
	if binPath == "" {
		binPath = defaultBinPath
	}
	dir := filepath.Dir(binPath)
	tmp, err := os.CreateTemp(dir, ".ghostpsy.update.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}

	previous := binPath + previousSuffix
	if _, err := os.Stat(binPath); err == nil {
		// Best-effort rollback copy: ignore failures so a corrupt previous
		// does not block the swap.
		_ = os.Rename(binPath, previous)
	}
	if err := os.Rename(tmpPath, binPath); err != nil {
		cleanup()
		return fmt.Errorf("rename to %s: %w", binPath, err)
	}
	return nil
}

// refreshSudoRule rewrites the installed grant to match this binary.
//
// An update changes what the agent may run, and the sudo rule is what allows it.
// Written once at setup and never again, the rule silently falls behind: every
// command added after a machine was installed fails with "a password is
// required", and the machine keeps whatever the agent could do on the day it
// arrived. Measured on a test host, five times in one afternoon.
//
// So the grant travels with the binary. This is the right place for it and the
// only safe one: `update` already runs as root and already replaces a root-owned
// file, so nothing here is a privilege the caller did not have a moment ago. The
// agent's own service user still cannot touch the grant — if it could, the file
// would no longer be a contract anybody could rely on.
//
// A machine with no grant is left alone. Absent means somebody chose not to give
// this agent any privileges, or it was never set up, and an update is not the
// moment to decide otherwise on their behalf.
func refreshSudoRule(path string, run runner) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return installSudoRule(path, sudoersFile(), run)
}
