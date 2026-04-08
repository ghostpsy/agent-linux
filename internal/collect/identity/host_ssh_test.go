//go:build linux

package identity

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

func TestParseSSHDTOutputExtendedDirectives(t *testing.T) {
	output := []byte(`
maxauthtries 6
clientaliveinterval 0
clientalivecountmax 3
allowusers 
denyusers root
subsystem sftp /usr/lib/openssh/sftp-server
usepam yes
x11forwarding no
`)

	cfg := parseSSHDTOutput(output)
	if cfg.maxAuthTries == nil || *cfg.maxAuthTries != 6 {
		t.Fatalf("expected max authtries 6, got %v", cfg.maxAuthTries)
	}
	if cfg.clientAliveInterval == nil || *cfg.clientAliveInterval != 0 {
		t.Fatalf("expected client alive interval 0, got %v", cfg.clientAliveInterval)
	}
	if cfg.clientAliveCountMax == nil || *cfg.clientAliveCountMax != 3 {
		t.Fatalf("expected client alive count max 3, got %v", cfg.clientAliveCountMax)
	}
	if cfg.allowUsersRaw != "" {
		t.Fatalf("expected empty allowusers, got %q", cfg.allowUsersRaw)
	}
	if cfg.denyUsersRaw != "root" {
		t.Fatalf("expected denyusers root, got %q", cfg.denyUsersRaw)
	}
	if cfg.subsystem == "" {
		t.Fatalf("expected subsystem")
	}
	if cfg.usePAM != "yes" {
		t.Fatalf("expected usepam yes, got %q", cfg.usePAM)
	}
	if cfg.x11Forwarding != "no" {
		t.Fatalf("expected x11forwarding no, got %q", cfg.x11Forwarding)
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
		maxAuthTries:    intPtr(4),
		allowUsersRaw:   "alice bob",
		denyUsersRaw:    "",
		subsystem:       "sftp internal-sftp",
		usePAM:          "yes",
		x11Forwarding:   "no",
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
	if out.MaxAuthTries == nil || *out.MaxAuthTries != 4 {
		t.Fatalf("expected max auth tries 4, got %v", out.MaxAuthTries)
	}
	if out.AllowUsersPresent == nil || !*out.AllowUsersPresent {
		t.Fatalf("expected allow users present")
	}
	if out.DenyUsersPresent == nil || *out.DenyUsersPresent {
		t.Fatalf("expected deny users absent")
	}
	if out.UsePAM != "yes" {
		t.Fatalf("expected use_pam yes, got %q", out.UsePAM)
	}
	if out.X11Forwarding != "no" {
		t.Fatalf("expected x11_forwarding no, got %q", out.X11Forwarding)
	}
}
