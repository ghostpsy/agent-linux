//go:build linux

package firewall

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

// This used to assert that family "ufw" means active, and that is the bug it was
// holding in place. The family is set when `ufw status` says active *or*
// /etc/ufw/ufw.conf says ENABLED=yes, so a machine carrying the flag and
// filtering nothing was reported as protected.
//
// ufw is now decided by what it is really doing — see the cases below. The other
// families are unchanged.
func TestApplyFirewallActive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		family string
		want   bool
	}{
		{fwFirewalld, true},
		{fwIptables, false},
		{fwNftables, false},
		{fwNoneDetected, false},
	}
	for _, tc := range cases {
		fw := &payload.Firewall{Family: tc.family}
		applyFirewallActiveFrom(fw, false)
		if fw.Active != tc.want {
			t.Fatalf("family %q: active=%v, want %v", tc.family, fw.Active, tc.want)
		}
	}
	applyFirewallActiveFrom(nil, false)
}

// TestAFirewallEnforcingNothingIsNotActive is the false report this fixes.
//
// Measured on a real Ubuntu 24.04 left with ENABLED=yes and no chains loaded:
// `ufw status` said inactive, `iptables -L` held no ufw-user chain, and the scan
// reported "active": true. The machine had no firewall and its report said it
// did.
func TestAFirewallEnforcingNothingIsNotActive(t *testing.T) {
	t.Parallel()
	fw := &payload.Firewall{
		Family:                 fwUfw,
		UfwStatusVerboseSample: []string{"Status: inactive"},
	}
	// The configuration says on. What it is doing says off.
	applyFirewallActiveFrom(fw, true)

	if fw.Active {
		t.Error("a firewall enforcing nothing was reported as active")
	}
	if fw.ConfiguredOn == nil || !*fw.ConfiguredOn {
		t.Error("the configuration's own claim was not kept")
	}
}

func TestAFirewallThatIsReallyOnIsActive(t *testing.T) {
	t.Parallel()
	fw := &payload.Firewall{
		Family:                 fwUfw,
		UfwStatusVerboseSample: []string{"Status: active", "Default: deny (incoming), allow (outgoing)"},
	}
	applyFirewallActiveFrom(fw, true)

	if !fw.Active {
		t.Error("a firewall that is filtering was reported as inactive")
	}
}

// Unprivileged `ufw status` answers "ERROR: You need to be root", so on a machine
// where the privileged read fails there is no status to believe. The
// configuration is then the only thing there is, which is why the family is set
// from it in the first place.
func TestWithNoReadableStatusTheConfigurationDecides(t *testing.T) {
	t.Parallel()
	for _, persisted := range []bool{true, false} {
		fw := &payload.Firewall{Family: fwUfw}
		applyFirewallActiveFrom(fw, persisted)
		if fw.Active != persisted {
			t.Errorf("no readable status, configuration=%v: active=%v", persisted, fw.Active)
		}
	}
}

// "inactive" contains "active". Reading them in the wrong order would call every
// switched-off firewall active, which is the whole mistake.
func TestInactiveIsNotReadAsActive(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		lines []string
		want  string
	}{
		{[]string{"Status: inactive"}, ufwStatusInactiveText},
		{[]string{"Status: active"}, ufwStatusActiveText},
		{[]string{"status: ACTIVE"}, ufwStatusActiveText},
		{[]string{"To  Action  From", "22/tcp  ALLOW  Anywhere"}, ufwStatusUnknownText},
		{nil, ufwStatusUnknownText},
	} {
		if got := ufwStatusFromVerbose(tc.lines); got != tc.want {
			t.Errorf("ufwStatusFromVerbose(%v) = %q, want %q", tc.lines, got, tc.want)
		}
	}
}
