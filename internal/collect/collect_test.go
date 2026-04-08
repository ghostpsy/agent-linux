//go:build linux

package collect

import (
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestSoftwarePackagesHostRuntimesNilWhenEmpty(t *testing.T) {
	hr := &payload.HostRuntimes{Items: []payload.RuntimeEntry{}}
	if got := softwarePackagesHostRuntimes(hr); got != nil {
		t.Fatalf("expected nil when no items and no error, got %+v", got)
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
	if got == nil || len(got.Items) != 0 || got.Docker == nil || got.Kubelet != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestContainerCloudHostRuntimesWithKubelet(t *testing.T) {
	hr := &payload.HostRuntimes{
		Items:   []payload.RuntimeEntry{{Kind: "go"}},
		Kubelet: &payload.KubeletNodeFingerprint{KubeletBinaryPath: "/usr/bin/kubelet"},
	}
	got := containerCloudHostRuntimes(hr)
	if got == nil || len(got.Items) != 0 || got.Kubelet == nil || got.Docker != nil {
		t.Fatalf("got %+v", got)
	}
}
