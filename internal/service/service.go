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
func upstartJob(s Spec) string {
	return fmt.Sprintf(`# ghostpsy agent
description "ghostpsy agent"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 60

setuid %s

%sexec %s
`, s.User, upstartEnvironment(s.Env), s.ExecStart)
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
