//go:build linux

package apache

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestOptionsLineEnablesIndexes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want bool
	}{
		{"Options Indexes FollowSymLinks", true},
		{"Options FollowSymLinks -Indexes", false},
		{"Options -Indexes +FollowSymLinks", false},
		{"Options All", true},
		{"Options FollowSymLinks", false},
		{"  Options  +Indexes  ", true},
	}
	for _, tc := range cases {
		if got := optionsLineEnablesIndexes(tc.line); got != tc.want {
			t.Fatalf("%q: got %v want %v", tc.line, got, tc.want)
		}
	}
}

func TestApacheDedupCapPaths_EmptyInputNonNilSlice(t *testing.T) {
	t.Parallel()
	got := apacheDedupCapPaths([]string{})
	if got == nil {
		t.Fatal("expected non-nil empty slice so JSON encodes [] not null")
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %#v", got)
	}
}

func TestApacheRiskyLoaded_EmptyNonNilSlice(t *testing.T) {
	t.Parallel()
	got := apacheRiskyLoaded(map[string]struct{}{})
	if got == nil {
		t.Fatal("expected non-nil empty slice for ingest schema array fields")
	}
	if len(got) != 0 {
		t.Fatal("expected no risky modules")
	}
}

func TestApplyApacheLeakageAndTrace(t *testing.T) {
	t.Parallel()
	merged := "TraceEnable Off\nServerTokens Prod\nServerSignature Off\n"
	out := &payload.ApacheHttpdPosture{}
	applyApacheLeakageAndTrace(merged, out)
	if out.TraceEnabled == nil || *out.TraceEnabled {
		t.Fatalf("trace_enabled: %v", out.TraceEnabled)
	}
	if out.ServerTokens == nil || *out.ServerTokens != "Prod" {
		t.Fatalf("server_tokens: %v", out.ServerTokens)
	}
	if out.ServerSignature == nil || *out.ServerSignature != "Off" {
		t.Fatalf("server_signature: %v", out.ServerSignature)
	}
}
