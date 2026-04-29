package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_SignsSha256SumsFile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envPrivateKey, hex.EncodeToString(priv))

	dir := t.TempDir()
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	sums := []byte("abc123  ghostpsy_0.36.0_linux_amd64\n")
	if err := os.WriteFile(sumsPath, sums, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{sumsPath}); err != nil {
		t.Fatalf("run: %v", err)
	}

	sigBytes, err := os.ReadFile(sumsPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigBytes)))
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, sums, sig) {
		t.Fatal("ed25519.Verify rejected the signature produced by sign-release")
	}
}

func TestRun_RejectsWhenEnvMissing(t *testing.T) {
	t.Setenv(envPrivateKey, "")
	dir := t.TempDir()
	p := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{p}); err == nil {
		t.Fatal("expected error when private key env is missing")
	}
}

func TestRun_RejectsBadKey(t *testing.T) {
	t.Setenv(envPrivateKey, "not-hex")
	dir := t.TempDir()
	p := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{p}); err == nil {
		t.Fatal("expected error on malformed key")
	}
}

func TestRun_RejectsWrongKeySize(t *testing.T) {
	t.Setenv(envPrivateKey, hex.EncodeToString([]byte("too-short")))
	dir := t.TempDir()
	p := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{p}); err == nil {
		t.Fatal("expected error on undersized key")
	}
}
