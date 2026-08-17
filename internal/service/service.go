//go:build linux

// Package service installs the agent as a background service, on whichever
// init system the host actually has.
//
// The agent has to keep running rather than fire once, because Solve needs it
// to be there when a fix is approved — a daily timer cannot answer a click. And
// it has to work on hosts older than systemd, because the neglected servers our
// users inherited are exactly those hosts.
//
// Nothing outside this package knows which init system is in use.
package service

import (
	"fmt"
	"strings"
)

// Spec is what any init system needs to be told about the agent.
//
// Env carries KEY=value settings the running service needs. It exists because
// the agent registers against one address and would otherwise report to
// another: the address is known at install time and forgotten by the time the
// service starts, unless the init system is told to pass it on.
type Spec struct {
	ExecStart string
	User      string
	Env       []string
}

// systemdUnit renders the unit for systemd hosts: Debian 8+, Ubuntu 15.04+,
// RHEL/CentOS 7+, Fedora, SUSE 12+.
//
// It is deliberately less hardened than a reviewer will expect. NoNewPrivileges
// breaks sudo outright, and ProtectSystem=strict blocks reads the collectors
// need — and every privileged read the agent makes goes through sudo. The real
// boundary is the sudoers allowlist in /etc/sudoers.d/ghostpsy, which a person
// can read, not a list of directives in here.
func systemdUnit(s Spec) string {
	return fmt.Sprintf(`[Unit]
Description=ghostpsy agent
Documentation=https://doc.ghostpsy.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
%sExecStart=%s
Restart=always
RestartSec=30

# Deliberately absent: NoNewPrivileges and ProtectSystem=strict.
# Both break the sudo this agent depends on for every privileged read.
# The privilege boundary is /etc/sudoers.d/ghostpsy, not this file.
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, s.User, systemdEnvironment(s.Env), s.ExecStart)
}

// systemdEnvironment renders one quoted Environment= line per setting, or
// nothing at all. Values can hold characters systemd would otherwise split on,
// so they are quoted.
func systemdEnvironment(env []string) string {
	var b strings.Builder
	for _, kv := range env {
		fmt.Fprintf(&b, "Environment=%q\n", kv)
	}
	return b.String()
}

// upstartJob renders the job for RHEL/CentOS 6 and Ubuntu 9.10-14.10.
//
// respawn is the reason Upstart is supported at all: without something to
// restart a crashed agent the machine simply goes quiet, and nobody notices
// until they look.
//
// Privilege is dropped with su rather than the setuid stanza. setuid arrived in
// Upstart 1.4; CentOS 6 ships 0.6.5, which does not ignore it but rejects the
// entire job — `initctl start ghostpsy` answered "Unknown job" while the file
// sat in /etc/init looking perfectly correct. Measured on a real CentOS 6.10:
// deleting that one line made the same job load.
//
// `exec su ... -c 'exec ...'` matters in both places. The outer exec replaces
// the job's shell with su, the inner one replaces su with the agent, so what
// Upstart watches and respawns is the agent itself and not a shell holding it.
//
// -m keeps the environment across the change of user. Without it the env lines
// above are discarded, and a machine set up against a staging server would go
// back to reporting to the public one.
func upstartJob(s Spec) string {
	return fmt.Sprintf(`# ghostpsy agent
description "ghostpsy agent"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 60

# Not "setuid %s": Upstart 0.6.5 on CentOS 6 rejects the whole job over it.
%sexec su -m -s /bin/sh -c 'exec %s' %s
`, s.User, upstartEnvironment(s.Env), s.ExecStart, s.User)
}

// upstartEnvironment renders Upstart's own form of the same thing. Upstart has
// no quoting here, which is fine: the only values we pass are URLs.
func upstartEnvironment(env []string) string {
	var b strings.Builder
	for _, kv := range env {
		fmt.Fprintf(&b, "env %s\n", kv)
	}
	return b.String()
}
