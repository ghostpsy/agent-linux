//go:build linux

package collect

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestSoftwarePackagesHostRuntimesEmptyItemsStillEmitted(t *testing.T) {
	hr := &payload.HostRuntimes{Items: []payload.RuntimeEntry{}}
	got := softwarePackagesHostRuntimes(hr)
	if got == nil || len(got.Items) != 0 {
		t.Fatalf("expected empty items slice, got %+v", got)
	}
}

func TestSoftwarePackagesHostRuntimesOmitsDockerKubelet(t *testing.T) {
	hr := &payload.HostRuntimes{
		Items:  []payload.RuntimeEntry{{Kind: "python", Version: "3", BinaryPath: "/usr/bin/python3", ManagedBy: "package"}},
		Docker: &payload.DockerHostFingerprint{DockerCliPath: "/usr/bin/docker"},
	}
	got := softwarePackagesHostRuntimes(hr)
	if got == nil || len(got.Items) != 1 || got.Docker != nil || got.Kubelet != nil {
		t.Fatalf("expected items only, got %+v", got)
	}
}

func TestContainerCloudHostRuntimesNilWithoutSignals(t *testing.T) {
	hr := &payload.HostRuntimes{Items: []payload.RuntimeEntry{{Kind: "python"}}}
	if got := containerCloudHostRuntimes(hr); got != nil {
		t.Fatalf("expected nil without docker/kubelet, got %+v", got)
	}
}

func TestContainerCloudHostRuntimesWithDocker(t *testing.T) {
	hr := &payload.HostRuntimes{
		Items:  []payload.RuntimeEntry{{Kind: "python"}},
		Docker: &payload.DockerHostFingerprint{DockerCliPath: "/usr/bin/docker"},
	}
	got := containerCloudHostRuntimes(hr)
	if got == nil || got.Docker == nil || got.Kubelet != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestContainerCloudHostRuntimesWithKubelet(t *testing.T) {
	hr := &payload.HostRuntimes{
		Items:   []payload.RuntimeEntry{{Kind: "go"}},
		Kubelet: &payload.KubeletNodeFingerprint{KubeletBinaryPath: "/usr/bin/kubelet"},
	}
	got := containerCloudHostRuntimes(hr)
	if got == nil || got.Kubelet == nil || got.Docker != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestCryptographyNotifyCount(t *testing.T) {
	c := payload.CryptographyComponent{}
	if cryptographyNotifyCount(c) != 0 {
		t.Fatalf("expected 0, got %d", cryptographyNotifyCount(c))
	}
	c.LocalTlsCertInventory = &payload.LocalTlsCertInventory{
		Items: []payload.LocalTlsCertFileEntry{{Path: "/x.pem", NotAfter: "2099-01-01T00:00:00Z"}},
	}
	if cryptographyNotifyCount(c) != 1 {
		t.Fatalf("expected 1, got %d", cryptographyNotifyCount(c))
	}
}

func TestLoggingAuditNotifyCount(t *testing.T) {
	pct := 50
	journalActive := true
	atdInactive := false
	c := payload.LoggingAndSystemAuditingComponent{
		SyslogForwarding: &payload.SyslogForwardingPosture{
			Daemons: []payload.SyslogDaemonEntry{{Implementation: "rsyslog"}},
		},
		Journald:      &payload.JournaldPosture{UnitActive: &journalActive},
		Auditd:        &payload.AuditdPosture{},
		LogrotateDisk: &payload.LogrotateDiskPosture{VarLogMountUsedPct: &pct},
		AtBatch:       &payload.AtBatchPosture{AtdUnitActive: &atdInactive},
		ProcessAccounting: &payload.ProcessAccountingPosture{
			SadcOnPath: true,
		},
	}
	if n := loggingAuditNotifyCount(c); n != 6 {
		t.Fatalf("expected 6 groups counted, got %d", n)
	}
}
