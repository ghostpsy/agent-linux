//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/version"
)

// pinVersion sets version.Version for the duration of one test and restores
// the previous value on cleanup. Tests that check the kill-switch must pin
// because the default ``dev`` placeholder is special-cased to skip.
func pinVersion(t *testing.T, v string) {
	t.Helper()
	prev := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = prev })
}

func TestEnforceMinSupportedVersion_AllowsCurrent(t *testing.T) {
	pinVersion(t, "0.36.0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(updateCheckResponse{
			LatestVersion:       "0.36.0",
			MinSupportedVersion: "0.34.0",
			DownloadURL:         "https://example/bin",
		})
	}))
	defer srv.Close()
	if err := enforceMinSupportedVersion(context.Background(), srv.URL); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestEnforceMinSupportedVersion_BlocksTooOld(t *testing.T) {
	pinVersion(t, "0.30.0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(updateCheckResponse{
			LatestVersion:       "0.36.0",
			MinSupportedVersion: "0.34.0",
			DownloadURL:         "https://example/bin",
		})
	}))
	defer srv.Close()
	if err := enforceMinSupportedVersion(context.Background(), srv.URL); err == nil {
		t.Fatal("expected min-version error when current is below floor")
	}
}

func TestEnforceMinSupportedVersion_DevBuildIsSkipped(t *testing.T) {
	// version.Version defaults to "dev" in this test process; assert the
	// special-case explicitly for clarity.
	pinVersion(t, "dev")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(updateCheckResponse{
			LatestVersion:       "9.99.99",
			MinSupportedVersion: "9.99.99",
			DownloadURL:         "https://example/bin",
		})
	}))
	defer srv.Close()
	if err := enforceMinSupportedVersion(context.Background(), srv.URL); err != nil {
		t.Fatalf("dev build must skip the kill-switch, got %v", err)
	}
}

func TestEnforceMinSupportedVersion_FailOpenOnNetworkError(t *testing.T) {
	pinVersion(t, "0.30.0")
	if err := enforceMinSupportedVersion(context.Background(), "http://127.0.0.1:1"); err != nil {
		t.Fatalf("expected fail-open on network error, got %v", err)
	}
}

func TestEnforceMinSupportedVersion_SkipFlag(t *testing.T) {
	pinVersion(t, "0.30.0")
	t.Setenv(envSkipMinVersionCheck, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(updateCheckResponse{
			LatestVersion:       "9.99.99",
			MinSupportedVersion: "9.99.99",
			DownloadURL:         "https://example/bin",
		})
	}))
	defer srv.Close()
	if err := enforceMinSupportedVersion(context.Background(), srv.URL); err != nil {
		t.Fatalf("skip flag should bypass check, got %v", err)
	}
}
