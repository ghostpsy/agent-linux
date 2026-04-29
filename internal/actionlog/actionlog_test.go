//go:build linux

package actionlog

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerRedactsSensitiveFields(t *testing.T) {
	var out bytes.Buffer
	logger := New(true, &out)
	logger.Step(classificationExternalSend, "https://api.example.com/v1/ingest", "Sending payload to ingest API", map[string]string{
		"token":       "abc123",
		"contentType": "application/json",
	})
	logger.Note("Authorization prepared", map[string]string{"authorization": "Bearer xyz"})

	got := out.String()
	if !strings.Contains(got, "token=[REDACTED]") {
		t.Fatalf("expected token to be redacted, got: %s", got)
	}
	if !strings.Contains(got, "authorization=[REDACTED]") {
		t.Fatalf("expected authorization to be redacted, got: %s", got)
	}
	if strings.Contains(got, "abc123") || strings.Contains(got, "Bearer xyz") {
		t.Fatalf("expected secrets hidden, got: %s", got)
	}
}

func TestLoggerSummaryCounters(t *testing.T) {
	var out bytes.Buffer
	logger := New(true, &out)
	logger.Step(classificationLocalRead, "host.network", "Reading network interfaces", nil)
	logger.Step(classificationLocalModify, "/var/lib/ghostpsy/state.json", "Saving local state", nil)
	logger.Step(classificationExternalSend, "https://api.example.com/v1/ingest", "Sending payload", nil)
	logger.PrintSummary()

	got := out.String()
	if !strings.Contains(got, "files_read_count=1") {
		t.Fatalf("expected files_read_count=1, got: %s", got)
	}
	if !strings.Contains(got, "write_modify_actions_count=1") {
		t.Fatalf("expected write_modify_actions_count=1, got: %s", got)
	}
	if !strings.Contains(got, "external_requests_count=1") {
		t.Fatalf("expected external_requests_count=1, got: %s", got)
	}
	if !strings.Contains(got, "external_domains=api.example.com") {
		t.Fatalf("expected external domain summary, got: %s", got)
	}
}
