//go:build linux

package logging

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestParseLogrotatePathsFromBody(t *testing.T) {
	body := `# c
/var/log/syslog {
  rotate 4
}
/var/log/nginx/*.log /var/log/extra.log {
  weekly
}
`
	got := parseLogrotatePathsFromBody(body)
	want := []string{"/var/log/syslog", "/var/log/nginx/*.log", "/var/log/extra.log"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLogrotatePatternCoversFile(t *testing.T) {
	patterns := []string{"/var/log/nginx/*.log", "/var/log/syslog"}
	if !logrotatePatternCoversFile(patterns, "/var/log/nginx/access.log") {
		t.Fatal("expected glob match")
	}
	if !logrotatePatternCoversFile(patterns, "/var/log/syslog") {
		t.Fatal("expected exact match")
	}
	if logrotatePatternCoversFile(patterns, "/var/log/orphan.log") {
		t.Fatal("expected no match")
	}
}

func TestLogrotatePatternCoversFile_InvalidPatternIgnored(t *testing.T) {
	if logrotatePatternCoversFile([]string{"["}, "/var/log/x") {
		t.Fatal("invalid pattern should not match")
	}
}

func TestFilepathMatchBehavior(t *testing.T) {
	ok, err := filepath.Match("/var/log/*.log", "/var/log/foo.log")
	if err != nil || !ok {
		t.Fatalf("match=%v err=%v", ok, err)
	}
}
