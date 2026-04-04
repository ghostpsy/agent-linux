package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestDisplayGOARCH_maps386ToI386(t *testing.T) {
	want := runtime.GOARCH
	if want == "386" {
		want = "i386"
	}
	if got := DisplayGOARCH(); got != want {
		t.Fatalf("DisplayGOARCH()=%q want %q (runtime.GOARCH=%q)", got, want, runtime.GOARCH)
	}
}

func TestSummary_containsLabels(t *testing.T) {
	s := Summary()
	for _, sub := range []string{"version", "release date", "architecture"} {
		if !strings.Contains(s, sub) {
			t.Fatalf("summary missing %q: %q", sub, s)
		}
	}
}
