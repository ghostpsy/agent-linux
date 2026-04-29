package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func makeKeypair(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func TestVerifyShaSums_OK(t *testing.T) {
	pubHex, priv := makeKeypair(t)
	t.Setenv(envPublicKeyOverride, pubHex)
	sums := []byte("abc123  ghostpsy_0.36.0_linux_amd64\n")
	sig := ed25519.Sign(priv, sums)
	if err := VerifyShaSums(sums, hex.EncodeToString(sig)); err != nil {
		t.Fatalf("expected verify ok, got %v", err)
	}
}

func TestVerifyShaSums_TamperedContent(t *testing.T) {
	pubHex, priv := makeKeypair(t)
	t.Setenv(envPublicKeyOverride, pubHex)
	sums := []byte("abc123  ghostpsy_0.36.0_linux_amd64\n")
	sig := ed25519.Sign(priv, sums)
	tampered := []byte("def456  ghostpsy_0.36.0_linux_amd64\n")
	if err := VerifyShaSums(tampered, hex.EncodeToString(sig)); err == nil {
		t.Fatal("expected verify to fail on tampered content")
	}
}

func TestVerifyShaSums_TamperedSignature(t *testing.T) {
	pubHex, priv := makeKeypair(t)
	t.Setenv(envPublicKeyOverride, pubHex)
	sums := []byte("abc123  ghostpsy_0.36.0_linux_amd64\n")
	sig := ed25519.Sign(priv, sums)
	sig[0] ^= 0xFF
	if err := VerifyShaSums(sums, hex.EncodeToString(sig)); err == nil {
		t.Fatal("expected verify to fail on tampered signature")
	}
}

func TestVerifyShaSums_NoKeyConfigured(t *testing.T) {
	t.Setenv(envPublicKeyOverride, "")
	if err := VerifyShaSums([]byte("x"), strings.Repeat("ab", 64)); err == nil {
		t.Fatal("expected ErrSigningNotConfigured when no key is set")
	}
}

func TestVerifyBinaryHash_OK(t *testing.T) {
	data := []byte("binary-content")
	hash := HashBinary(data)
	sums := []byte(hash + "  ghostpsy_0.36.0_linux_amd64\n")
	if err := VerifyBinaryHash(sums, "ghostpsy_0.36.0_linux_amd64", data); err != nil {
		t.Fatalf("expected verify ok, got %v", err)
	}
}

func TestVerifyBinaryHash_Mismatch(t *testing.T) {
	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  bin\n")
	if err := VerifyBinaryHash(sums, "bin", []byte("not the same data")); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyBinaryHash_FilenameMissing(t *testing.T) {
	sums := []byte("00ff  another-file\n")
	if err := VerifyBinaryHash(sums, "missing", []byte("x")); err == nil {
		t.Fatal("expected error when filename not in SHA256SUMS")
	}
}

func TestVerifyBinaryHash_HandlesBinaryStarPrefix(t *testing.T) {
	data := []byte("z")
	sums := []byte(HashBinary(data) + " *bin\n")
	if err := VerifyBinaryHash(sums, "bin", data); err != nil {
		t.Fatalf("expected ok with star-prefixed filename, got %v", err)
	}
}
