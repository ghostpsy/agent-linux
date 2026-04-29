// sign-release signs a SHA256SUMS file with the release Ed25519 private key.
//
// Usage (typically inside the release workflow):
//
//	GHOSTPSY_RELEASE_SIGNING_KEY_HEX=<hex> go run ./scripts/sign-release path/to/SHA256SUMS
//
// Writes ``path/to/SHA256SUMS.sig`` containing the hex-encoded Ed25519
// signature over the file content. The agent verifies this with the
// matching public key embedded in the binary.
//
// Exits non-zero if the env var is missing, the key is malformed, the
// input file cannot be read, or the output file cannot be written.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const envPrivateKey = "GHOSTPSY_RELEASE_SIGNING_KEY_HEX"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sign-release: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sign-release <SHA256SUMS-path>")
	}
	keyHex := strings.TrimSpace(os.Getenv(envPrivateKey))
	if keyHex == "" {
		return fmt.Errorf("%s is not set", envPrivateKey)
	}
	priv, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf(
			"private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv),
		)
	}

	in := args[0]
	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)

	out := in + ".sig"
	if err := os.WriteFile(out, []byte(hex.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Println(out)
	return nil
}
