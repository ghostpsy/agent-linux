//go:build linux

package privexec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/confedit"
)

// One declared command per service, not one command taking any service.
//
// `systemctl restart *` granted a restart of anything on the machine. The rule that
// replaces it came from the person paying for this: **ghostpsy may restart only what
// it configures.**
//
// That rule is not only about the grant file. It is about competence. We cannot see
// what nginx is serving or what a restart of it interrupts, so "systemd says it
// failed, so restart it" is a guess dressed up as a fix. Where we wrote the
// configuration, we know what changed and why a reload is needed. Where we did not,
// the honest answer is the command and a look at `systemctl status` first.
//
// Two sources, and both are declarations rather than a list somebody maintains:
//
//   - the services whose configuration we write, from confedit
//   - the services our own actions switch on and off, below
//
// A restart also has to be undoable, so `stop` covers the same set: an action that
// started something that was not running puts it back by stopping it.

// unitsWeManage are the services ghostpsy switches on and off.
//
// Each one is here because an action manages it, and for no other reason. ufw and
// firewalld are the two firewalls enable_firewall knows; the last two are what
// enable_automatic_security_updates switches on, one name per distribution family.
// ntp and chronyd are what ensure_time_sync switches on, one name per
// distribution family, the same way the update services are.
var unitsWeManage = []string{
	"ufw", "firewalld", "unattended-upgrades", "dnf-automatic.timer", "ntp", "chronyd",
}

// ServiceReload names the command that makes a service re-read its configuration.
//
// Passing a placeholder builds the template a step uses, so the catalogue and the
// grant cannot disagree about the shape of an ID.
func ServiceReload(unit string) ID { return ID("service.reload." + unit) }

// ServiceRestart names the command that stops and starts a service.
func ServiceRestart(unit string) ID { return ID("service.restart." + unit) }

// ServiceStop names the command that stops a service, which is how a restart is undone.
func ServiceStop(unit string) ID { return ID("service.stop." + unit) }

// ServiceEnableNow starts a service and makes it start at boot.
func ServiceEnableNow(unit string) ID { return ID("service.enable_now." + unit) }

// ServiceDisableNow stops a service and stops it starting at boot.
func ServiceDisableNow(unit string) ID { return ID("service.disable_now." + unit) }

// unitsWeConfigure are the services whose configuration files ghostpsy writes.
func unitsWeConfigure() []string {
	var units []string
	for _, s := range confedit.All() {
		for _, unit := range s.Units {
			if !slices.Contains(units, unit) {
				units = append(units, unit)
			}
		}
	}
	return units
}

func init() {
	configured := unitsWeConfigure()

	for _, unit := range configured {
		declare(ServiceReload(unit), Command{
			Binary: "systemctl",
			Args:   []string{"reload", unit},
			Why: fmt.Sprintf("ask %s to read its configuration again, after ghostpsy has "+
				"changed it. A reload keeps existing connections; a restart would not", unit),
			Env:       localeC,
			NeedsPath: UnitPath(unit),
		})
	}

	// A restart, and the stop that undoes it, for everything we either configure or
	// switch on. Nothing else on the machine.
	for _, unit := range append(slices.Clone(configured), unitsWeManage...) {
		declare(ServiceRestart(unit), Command{
			Binary: "systemctl",
			Args:   []string{"restart", unit},
			Why: fmt.Sprintf("restart %s, which ghostpsy configures, so it knows what changed "+
				"and what a restart affects", unit),
			Env:       localeC,
			NeedsPath: UnitPath(unit),
		})
		declare(ServiceStop(unit), Command{
			Binary:    "systemctl",
			Args:      []string{"stop", unit},
			Why:       fmt.Sprintf("stop %s again, to undo having started it", unit),
			Env:       localeC,
			NeedsPath: UnitPath(unit),
		})
	}

	// Switching a service on is only ever for the ones our own actions manage. Never
	// for SSH: switching that off is how a server stops being reachable at all.
	for _, unit := range unitsWeManage {
		declare(ServiceEnableNow(unit), Command{
			Binary:    "systemctl",
			Args:      []string{"enable", "--now", unit},
			Why:       fmt.Sprintf("start %s and have it start at boot", unit),
			Env:       localeC,
			NeedsPath: UnitPath(unit),
		})
		declare(ServiceDisableNow(unit), Command{
			Binary:    "systemctl",
			Args:      []string{"disable", "--now", unit},
			Why:       fmt.Sprintf("stop %s and stop it starting at boot, to undo having switched it on", unit),
			Env:       localeC,
			NeedsPath: UnitPath(unit),
		})
	}
}

// UnitPath is the unit file a grant depends on, so the file grants nothing for
// software this server does not have.
//
// A unit may live in either directory depending on whether the distribution shipped it
// or somebody added it, and NeedsPath takes one path — so this returns the packaged
// location, which is where every unit we name comes from. A hand-written unit in
// /etc/systemd/system is not something ghostpsy configures.
func UnitPath(unit string) string {
	name := unit
	if !strings.Contains(name, ".") {
		name += ".service"
	}
	return "/usr/lib/systemd/system/" + name
}
