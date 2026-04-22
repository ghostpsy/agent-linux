package payload

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContainerNativeHostRuntimes_MarshalJSON_OmitsItemsKey(t *testing.T) {
	cr := &ContainerNativeHostRuntimes{
		Docker: &DockerHostFingerprint{DockerCliPath: "/usr/bin/docker"},
	}
	b, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "items") {
		t.Fatalf("expected no items key, got %s", string(b))
	}
}

func TestContainerWorkloads_MarshalJSON_StableShape(t *testing.T) {
	w := &ContainerWorkloads{
		DockerContainers: []DockerContainerWorkload{
			{
				Name:              "web",
				ContainerID:       "deadbeef0001",
				Image:             "nginx:1.27",
				ImageTag:          "1.27",
				ImageDigestPinned: false,
				State:             "running",
				RestartCount:      0,
				WorkloadHint:      "web",
			},
		},
		KubeletPods: []KubeletPodWorkload{
			{
				Name:      "app",
				Namespace: "default",
				Phase:     "READY",
				Containers: []KubeletContainerWorkload{
					{Name: "app", Image: "ghcr.io/acme/app:1.0", ImageTag: "1.0"},
				},
			},
		},
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	// Structural markers the API relies on.
	for _, must := range []string{
		`"docker_containers"`,
		`"docker_containers_truncated"`,
		`"kubelet_pods"`,
		`"kubelet_pods_truncated"`,
		`"image_tag_is_latest"`,
		`"image_digest_pinned"`,
		`"workload_hint"`,
	} {
		if !strings.Contains(js, must) {
			t.Errorf("missing JSON key %s in: %s", must, js)
		}
	}
}

func TestContainerWorkloads_EmptyArraysSerialize(t *testing.T) {
	// An empty ContainerWorkloads (collector ran but found nothing) must
	// still serialize with its two arrays present, not null — otherwise
	// the API / UI would have to special-case absent keys.
	w := &ContainerWorkloads{
		DockerContainers: []DockerContainerWorkload{},
		KubeletPods:      []KubeletPodWorkload{},
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, `"docker_containers":[]`) {
		t.Errorf("expected docker_containers to serialize as [], got %s", js)
	}
	if !strings.Contains(js, `"kubelet_pods":[]`) {
		t.Errorf("expected kubelet_pods to serialize as [], got %s", js)
	}
}
