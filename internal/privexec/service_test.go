//go:build linux

package privexec

import (
	"strings"
	"testing"
)

// One declared command per service, not one command taking any service.
//
// `systemctl restart *` was a grant to restart anything on the machine. The rule that
// replaces it: **ghostpsy may restart only what it configures.** That is not only
// about the grant file — it is about competence. We have no idea what nginx is serving
// or what a restart interrupts, so "it failed, restart it" would be a guess dressed as
// a fix.

func TestNoServiceCommandThatChangesAnythingTakesAUnitParameter(t *testing.T) {
	for id, declared := range registry {
		if !strings.HasPrefix(string(id), "service.") || declared.Unprivileged {
			continue
		}
		if len(declared.Params) != 0 {
			t.Errorf("%s takes a parameter, so its grant is `systemctl ... *` again", id)
		}
	}
}

func TestWeMayRestartOnlyWhatWeConfigureOrManage(t *testing.T) {
	// Configured: we write their configuration files.
	// Managed: our firewall and automatic-update actions switch them on and off.
	for _, unit := range []string{"sshd", "ssh", "ufw", "firewalld", "unattended-upgrades"} {
		if !Declared(ServiceRestart(unit)) {
			t.Errorf("%s is a service ghostpsy changes, but it cannot restart it", unit)
		}
	}

	// The ones the rule protects us from. A restart here drops live connections or
	// takes down every container, and we cannot see the workload.
	for _, unit := range []string{"postgresql", "mysql", "mariadb", "docker", "nginx"} {
		if Declared(ServiceRestart(unit)) {
			t.Errorf("%s can be restarted, but ghostpsy does not configure it", unit)
		}
	}
}

func TestReloadIsOnlyForServicesWhoseConfigurationWeWrite(t *testing.T) {
	if !Declared(ServiceReload("sshd")) {
		t.Error("we write sshd's configuration, so we must be able to reload it")
	}
	// We switch ufw on, we do not write its configuration file, so there is nothing
	// to reload.
	if Declared(ServiceReload("ufw")) {
		t.Error("ufw can be reloaded, but ghostpsy does not write its configuration")
	}
}

func TestSwitchingAServiceOnIsOnlyForTheOnesOurActionsManage(t *testing.T) {
	for _, unit := range []string{"ufw", "firewalld", "unattended-upgrades"} {
		if !Declared(ServiceEnableNow(unit)) {
			t.Errorf("%s is switched on by an action, but there is no grant for it", unit)
		}
		if !Declared(ServiceDisableNow(unit)) {
			t.Errorf("%s cannot be switched off again, so the change cannot be undone", unit)
		}
	}
	// Never sshd. Switching SSH off is how a server stops being reachable at all.
	if Declared(ServiceDisableNow("sshd")) || Declared(ServiceDisableNow("ssh")) {
		t.Error("SSH can be switched off, which is how a server becomes unreachable")
	}
}

// The same trick the templated step commands use: passing a placeholder builds the
// template, so the catalogue and the grant cannot disagree about the ID's shape.
func TestTheSameFunctionBuildsTheTemplateAndTheRealID(t *testing.T) {
	if got := ServiceRestart("{unit}"); got != ID("service.restart.{unit}") {
		t.Errorf("template is %q", got)
	}
	if got := ServiceRestart("sshd"); got != ID("service.restart.sshd") {
		t.Errorf("real ID is %q", got)
	}
}
