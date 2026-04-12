//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestHumanMessageForCollectionAction_knownActions(t *testing.T) {
	t.Parallel()
	actions := []string{
		"collect_host_network",
		"collect_services",
		"collect_os_info",
		"collect_listeners",
		"collect_logging_and_system_auditing",
		"collect_nginx_posture",
		"collect_postfix_posture",
		"collect_mysql_posture",
		"collect_postgres_posture",
	}
	for _, a := range actions {
		msg := humanMessageForCollectionAction(a)
		if strings.Contains(msg, "Extracting allowlisted local system data") {
			t.Fatalf("action %q fell through to default: %q", a, msg)
		}
	}
}

func TestHumanDoneMessage_knownActions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		action string
		items  int
	}{
		{"collect_host_network", 2},
		{"collect_services", 5},
		{"collect_listeners", 3},
		{"collect_nginx_posture", 0},
		{"collect_nginx_posture", 1},
		{"collect_postfix_posture", 0},
		{"collect_postfix_posture", 1},
		{"collect_mysql_posture", 0},
		{"collect_mysql_posture", 1},
		{"collect_postgres_posture", 0},
		{"collect_postgres_posture", 1},
	}
	for _, tc := range cases {
		msg := humanDoneMessage(tc.action, tc.items)
		if msg == "" {
			t.Fatalf("empty done message for %q", tc.action)
		}
		if strings.HasPrefix(msg, "Done: extracted 0 entries.") && tc.items != 0 {
			t.Fatalf("unexpected default for %q: %s", tc.action, msg)
		}
	}
}
