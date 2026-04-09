//go:build linux

package logging

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestApplyJournaldConfLine(t *testing.T) {
	out := &payload.JournaldPosture{}
	applyJournaldConfLine(out, "Storage=persistent")
	if out.Storage != "persistent" {
		t.Fatalf("storage %q", out.Storage)
	}
	applyJournaldConfLine(out, "ForwardToSyslog=yes")
	if out.ForwardToSyslog == nil || !*out.ForwardToSyslog {
		t.Fatal("ForwardToSyslog")
	}
	applyJournaldConfLine(out, "Compress=no")
	if out.Compress == nil || *out.Compress {
		t.Fatal("Compress")
	}
	applyJournaldConfLine(out, "SystemMaxUse=500M")
	if out.SystemMaxUse != "500M" {
		t.Fatal(out.SystemMaxUse)
	}
	applyJournaldConfLine(out, "# comment")
	applyJournaldConfLine(out, "[Journal]")
}

func TestParseJournaldBool(t *testing.T) {
	if _, ok := parseJournaldBool("maybe"); ok {
		t.Fatal("expected false")
	}
}
