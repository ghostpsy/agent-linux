//go:build linux

package collect

import (
	"testing"
)

func TestParseSSHDTOutputReadsEffectiveDirectives(t *testing.T) {
	output := []byte(`
permitrootlogin no
passwordauthentication yes
kbdinteractiveauthentication no
listenaddress 0.0.0.0:22
listenaddress [::]:22
kexalgorithms curve25519-sha256,sntrup761x25519-sha512
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
`)

	cfg := parseSSHDTOutput(output)

	if cfg.permitRootLogin != "no" {
		t.Fatalf("expected PermitRootLogin no, got %q", cfg.permitRootLogin)
	}
	if cfg.passwordAuth != "yes" {
		t.Fatalf("expected PasswordAuthentication yes before Match, got %q", cfg.passwordAuth)
	}
	if cfg.challengeAuth != "no" {
		t.Fatalf("expected ChallengeResponseAuth no, got %q", cfg.challengeAuth)
	}
	if len(cfg.listenAddresses) != 2 {
		t.Fatalf("expected two listen addresses, got %d", len(cfg.listenAddresses))
	}
	if len(cfg.kexAlgorithms) != 2 {
		t.Fatalf("expected two KEX algorithms, got %d", len(cfg.kexAlgorithms))
	}
	if len(cfg.ciphers) != 2 {
		t.Fatalf("expected two ciphers, got %d", len(cfg.ciphers))
	}
}

func TestBuildHostSSHNormalizesAndCapsFields(t *testing.T) {
	cfg := sshdConfig{
		permitRootLogin: "Prohibit-Password",
		passwordAuth:    "No",
		challengeAuth:   "yes",
		listenAddresses: []string{" 0.0.0.0:22 ", "\"0.0.0.0:22\"", "[::]:22"},
		kexAlgorithms:   []string{"curve25519-sha256", "sntrup761x25519-sha512"},
		ciphers:         []string{"chacha20-poly1305@openssh.com"},
	}

	out := buildHostSSH(cfg)

	if out.PermitRootLogin != "prohibit-password" {
		t.Fatalf("expected normalized permit root login, got %q", out.PermitRootLogin)
	}
	if out.PasswordAuthentication != "no" {
		t.Fatalf("expected normalized password auth, got %q", out.PasswordAuthentication)
	}
	if out.ChallengeResponseAuth != "yes" {
		t.Fatalf("expected normalized challenge auth, got %q", out.ChallengeResponseAuth)
	}
	if len(out.ListenAddresses) != 2 {
		t.Fatalf("expected deduplicated listen addresses, got %d", len(out.ListenAddresses))
	}
	if out.MaxAuthTriesRecommended != 4 {
		t.Fatalf("expected max auth tries recommendation to stay 4, got %d", out.MaxAuthTriesRecommended)
	}
}
