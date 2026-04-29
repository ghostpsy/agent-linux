package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrSigningNotConfigured is returned when no public key is embedded and no
// override is set. The caller should refuse to install the artifact.
var ErrSigningNotConfigured = errors.New(
	"release signing not configured: no public key compiled in (set PublicKeyHex or " +
		"GHOSTPSY_RELEASE_PUBKEY_HEX)",
)

// resolvePublicKeyHex returns the hex public key from the env override
// (tests) or the compile-time constant (production builds).
func resolvePublicKeyHex() string {
	if v := strings.TrimSpace(os.Getenv(envPublicKeyOverride)); v != "" {
		return v
	}
	return PublicKeyHex
}

// VerifyShaSums checks that ``signatureHex`` is a valid Ed25519 signature
// over ``shaSumsContent`` produced by the release private key.
//
// ``signatureHex`` is the textual content of the ``SHA256SUMS.sig`` file:
// 64 hex bytes (128 characters), optionally surrounded by whitespace.
func VerifyShaSums(shaSumsContent []byte, signatureHex string) error {
	keyHex := resolvePublicKeyHex()
	if keyHex == "" {
		return ErrSigningNotConfigured
	}
	pub, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(pub),
		)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf(
			"signature must be %d bytes, got %d",
			ed25519.SignatureSize, len(sig),
		)
	}
	if !ed25519.Verify(pub, shaSumsContent, sig) {
		return errors.New("SHA256SUMS signature verification failed")
	}
	return nil
}

// HashBinary returns the lowercase hex SHA256 of ``data``, the format
// produced by ``sha256sum`` and used in the SHA256SUMS file.
func HashBinary(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VerifyBinaryHash checks that ``data`` matches the entry for ``filename``
// in a SHA256SUMS file. Lines look like ``<hex>  <name>``; surrounding
// whitespace and ``*`` (binary mode) are ignored.
func VerifyBinaryHash(shaSumsContent []byte, filename string, data []byte) error {
	want := ""
	for _, raw := range strings.Split(string(shaSumsContent), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Strip optional leading "*" (binary-mode marker).
		entryName := strings.TrimPrefix(fields[1], "*")
		if entryName == filename {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no SHA256SUMS entry for %q", filename)
	}
	got := HashBinary(data)
	if got != want {
		return fmt.Errorf(
			"hash mismatch for %s: got %s, want %s",
			filename, got, want,
		)
	}
	return nil
}
