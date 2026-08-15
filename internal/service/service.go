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

import "fmt"

// Spec is what any init system needs to be told about the agent.
type Spec struct {
	ExecStart string
	User      string
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
ExecStart=%s
Restart=always
RestartSec=30

# Deliberately absent: NoNewPrivileges and ProtectSystem=strict.
# Both break the sudo this agent depends on for every privileged read.
# The privilege boundary is /etc/sudoers.d/ghostpsy, not this file.
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, s.User, s.ExecStart)
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

exec %s
`, s.User, s.ExecStart)
}
