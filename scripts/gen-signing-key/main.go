// gen-signing-key prints a fresh Ed25519 keypair for signing releases.
//
// Run once during initial setup or when rotating the key:
//
//	go run ./scripts/gen-signing-key
//
// 1. Copy the printed PublicKeyHex into ``internal/release/pubkey.go``
//    and commit it.
// 2. Save the printed private key as the GitHub Actions secret
//    GHOSTPSY_RELEASE_SIGNING_KEY_HEX in the agent-linux repo settings.
// 3. Discard the local copy of the private key after saving — there is
//    no need to keep it on a workstation.
//
// The output is plain hex (no extra prefix), so paste only the digits
// into the secret value field.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate keypair: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("# Ed25519 release-signing keypair")
	fmt.Println()
	fmt.Println("# PublicKeyHex — paste into agent-linux/internal/release/pubkey.go and commit.")
	fmt.Println("# Public — safe to commit to source control.")
	fmt.Println(hex.EncodeToString(pub))
	fmt.Println()
	fmt.Println("# Private key — save as GitHub Actions secret GHOSTPSY_RELEASE_SIGNING_KEY_HEX.")
	fmt.Println("# Do NOT commit this value anywhere.")
	fmt.Println(hex.EncodeToString(priv))
}
