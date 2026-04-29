// Package release verifies Ed25519 signatures on release artifacts.
//
// The release workflow signs the SHA256SUMS file (which lists the hash of
// every binary in the release) with an Ed25519 private key stored as a
// GitHub Actions secret. The agent embeds the matching public key at build
// time and verifies the signature before trusting any binary it downloads
// for an auto-update.
//
// Key custody and rotation: see ../../README.md and
// the upstream docs/release-signing.md.
package release

// PublicKeyHex is the hex-encoded Ed25519 public key (32 raw bytes → 64 hex
// characters). Populated once by ``go run ./scripts/gen-signing-key``;
// the matching private key lives as the GitHub Actions secret
// GHOSTPSY_RELEASE_SIGNING_KEY_HEX.
const PublicKeyHex = "af463b2689f87712ce60446e0f82f3817f3c26269e0fccb978bd59a25a182ab6"

// envPublicKeyOverride lets unit tests inject a public key without
// rebuilding the binary. Production runs ignore this — set the constant
// above instead.
const envPublicKeyOverride = "GHOSTPSY_RELEASE_PUBKEY_HEX"
