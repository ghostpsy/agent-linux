//go:build linux

package software

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestScanKubeletConfigYAML(t *testing.T) {
	yaml := `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
readOnlyPort: 10255
protectKernelDefaults: true
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
`
	h := scanKubeletConfigYAML(yaml)
	if h.ReadOnlyPort == nil || *h.ReadOnlyPort != 10255 {
		t.Fatalf("readOnlyPort %+v", h.ReadOnlyPort)
	}
	if h.ProtectKernelDefaults == nil || !*h.ProtectKernelDefaults {
		t.Fatalf("protectKernelDefaults %+v", h.ProtectKernelDefaults)
	}
	if h.AnonymousAuthEnabled == nil || *h.AnonymousAuthEnabled {
		t.Fatalf("anonymous %+v", h.AnonymousAuthEnabled)
	}
}

func TestOverlayKubeletExecFlags(t *testing.T) {
	out := &payload.KubeletNodeFingerprint{}
	blob := `ExecStart=/usr/bin/kubelet --read-only-port=0 --protect-kernel-defaults=true --anonymous-auth=false`
	overlayKubeletExecFlags(out, blob)
	if out.ReadOnlyPort == nil || *out.ReadOnlyPort != 0 {
		t.Fatalf("readOnlyPort %+v", out.ReadOnlyPort)
	}
	if out.ProtectKernelDefaults == nil || !*out.ProtectKernelDefaults {
		t.Fatalf("pkd %+v", out.ProtectKernelDefaults)
	}
	if out.AnonymousAuthEnabled == nil || *out.AnonymousAuthEnabled {
		t.Fatalf("anon %+v", out.AnonymousAuthEnabled)
	}
}

func TestKubeletHintsOverlay(t *testing.T) {
	var a kubeletHints
	p440 := 440
	a.ReadOnlyPort = &p440
	tv := true
	b := kubeletHints{ReadOnlyPort: ptrInt(0), ProtectKernelDefaults: &tv}
	a.overlay(&b)
	if *a.ReadOnlyPort != 0 {
		t.Fatalf("want later override, got %d", *a.ReadOnlyPort)
	}
}

func ptrInt(v int) *int { return &v }
