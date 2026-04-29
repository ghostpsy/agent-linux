//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/release"
)

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.35.1", "0.36.0", true},
		{"0.36.0", "0.35.1", false},
		{"0.36.0", "0.36.0", false},
		{"1.0.0", "0.36.0", false},
		{"0.36.0", "1.0.0", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestFetchUpdateCheck_ParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/update-check" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("arch") == "" {
			http.Error(w, "missing arch", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(updateCheckResponse{
			LatestVersion:       "0.36.0",
			MinSupportedVersion: "0.34.0",
			DownloadURL:         "https://example/bin",
			Sha256SumsURL:       "https://example/sums",
			SignatureURL:        "https://example/sig",
			BinaryFilename:      "ghostpsy_0.36.0_linux_amd64",
		})
	}))
	defer srv.Close()
	got, err := fetchUpdateCheck(context.Background(), srv.URL, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got.LatestVersion != "0.36.0" {
		t.Fatalf("latest %q", got.LatestVersion)
	}
}

func TestFetchUpdateCheck_RejectsMissingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := fetchUpdateCheck(context.Background(), srv.URL, "amd64"); err == nil {
		t.Fatal("expected error on empty response")
	}
}

func TestInstallUpdate_VerifiesSignatureAndSwapsBinary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTPSY_RELEASE_PUBKEY_HEX", hex.EncodeToString(pub))

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "ghostpsy")
	if err := os.WriteFile(binPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTPSY_BIN_PATH", binPath)

	newBinary := []byte("new-binary-content")
	filename := "ghostpsy_0.36.0_linux_amd64"
	sums := []byte(release.HashBinary(newBinary) + "  " + filename + "\n")
	sig := hex.EncodeToString(ed25519.Sign(priv, sums))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sums":
			_, _ = w.Write(sums)
		case "/sig":
			_, _ = w.Write([]byte(sig))
		case "/bin":
			_, _ = w.Write(newBinary)
		default:
			http.Error(w, "404", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	info := &updateCheckResponse{
		LatestVersion:  "0.36.0",
		DownloadURL:    srv.URL + "/bin",
		Sha256SumsURL:  srv.URL + "/sums",
		SignatureURL:   srv.URL + "/sig",
		BinaryFilename: filename,
	}
	if err := installUpdate(context.Background(), info); err != nil {
		t.Fatalf("installUpdate: %v", err)
	}

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBinary) {
		t.Fatalf("new binary not in place")
	}
	prev, err := os.ReadFile(binPath + previousSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if string(prev) != "old" {
		t.Fatalf("previous binary not preserved")
	}
}

func TestInstallUpdate_RejectsTamperedBinary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTPSY_RELEASE_PUBKEY_HEX", hex.EncodeToString(pub))

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "ghostpsy")
	if err := os.WriteFile(binPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTPSY_BIN_PATH", binPath)

	expected := []byte("genuine")
	tampered := []byte("malicious")
	filename := "ghostpsy_0.36.0_linux_amd64"
	sums := []byte(release.HashBinary(expected) + "  " + filename + "\n")
	sig := hex.EncodeToString(ed25519.Sign(priv, sums))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sums":
			_, _ = w.Write(sums)
		case "/sig":
			_, _ = w.Write([]byte(sig))
		case "/bin":
			_, _ = w.Write(tampered)
		}
	}))
	defer srv.Close()

	info := &updateCheckResponse{
		LatestVersion:  "0.36.0",
		DownloadURL:    srv.URL + "/bin",
		Sha256SumsURL:  srv.URL + "/sums",
		SignatureURL:   srv.URL + "/sig",
		BinaryFilename: filename,
	}
	if err := installUpdate(context.Background(), info); err == nil {
		t.Fatal("expected hash mismatch error on tampered binary")
	}

	got, _ := os.ReadFile(binPath)
	if string(got) != "old" {
		t.Fatalf("binary should not have been replaced after verification failure; got %q", string(got))
	}
}
