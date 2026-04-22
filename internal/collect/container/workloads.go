//go:build linux

// Package container collects §6 container_and_cloud_native_linux data.
//
// workloads.go is the workload inventory (issue #135): running Docker
// containers and Kubernetes pods on the host, as opposed to
// docker_posture (security posture) or kubelet_fingerprint (daemon
// config). We expose *what is running* so the scan report can talk
// about the workloads as business assets, parallel to applications
// (issue #134).
package container

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	workloadsOverallTimeout = 20 * time.Second
	workloadsDockerCap      = 40
	workloadsKubeletCap     = 40
	workloadsWarningCap     = 8
)

// allowedWorkloadLabelPrefixes is the whitelist of Docker/Kubernetes label
// namespaces we are willing to ship back. Arbitrary user labels are
// dropped because they may carry secrets (tokens in value, config paths
// in keys, ops notes, etc.). We keep only namespaces that identify the
// *workload*, not its config.
var allowedWorkloadLabelPrefixes = []string{
	"com.docker.compose.",
	"com.docker.swarm.",
	"io.kubernetes.",
	"org.opencontainers.image.title",
	"org.opencontainers.image.version",
	"org.opencontainers.image.revision",
	"org.opencontainers.image.source",
	"org.opencontainers.image.vendor",
	"app.kubernetes.io/",
}

// dockerInspectShape is the slice of `docker inspect` output that we need
// for the workload view. Defined locally — intentionally narrower than
// the posture collector's shape, which pulls security fields.
type dockerInspectShape struct {
	ID              string `json:"Id"`
	Name            string `json:"Name"`
	RestartCount    int    `json:"RestartCount"`
	State           struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	Image  string `json:"Image"`
	Config struct {
		Image      string            `json:"Image"`
		User       string            `json:"User"`
		Entrypoint json.RawMessage   `json:"Entrypoint"`
		Cmd        json.RawMessage   `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
}

// crictlPod is the shape we read from `crictl pods --output json`.
type crictlPodList struct {
	Items []struct {
		ID        string `json:"id"`
		Metadata  struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		State     string `json:"state"`
		CreatedAt string `json:"createdAt"`
	} `json:"items"`
}

type crictlContainerList struct {
	Containers []struct {
		ID           string `json:"id"`
		PodSandboxID string `json:"podSandboxId"`
		Metadata     struct {
			Name         string `json:"name"`
			Attempt      int    `json:"attempt"`
		} `json:"metadata"`
		Image struct {
			Image string `json:"image"`
		} `json:"image"`
		ImageRef string `json:"imageRef"`
		State    string `json:"state"`
	} `json:"containers"`
}

// CollectContainerWorkloads runs the Docker + kubelet workload inventory.
// Returns nil when no container engine signal is detected on the host so
// the component serializes as {} rather than an empty object wrapping.
func CollectContainerWorkloads(ctx context.Context) *payload.ContainerWorkloads {
	subCtx, cancel := context.WithTimeout(ctx, workloadsOverallTimeout)
	defer cancel()

	out := &payload.ContainerWorkloads{
		DockerContainers: []payload.DockerContainerWorkload{},
		KubeletPods:      []payload.KubeletPodWorkload{},
	}
	ran := false

	if path, err := exec.LookPath("docker"); err == nil && path != "" {
		ran = true
		collectDockerWorkloads(subCtx, path, out)
	}
	if path, err := exec.LookPath("crictl"); err == nil && path != "" {
		ran = true
		collectCrictlWorkloads(subCtx, path, out)
	}

	if !ran {
		return nil
	}
	return out
}

func collectDockerWorkloads(ctx context.Context, dockerPath string, out *payload.ContainerWorkloads) {
	ids, more, err := dockerRunningIDsForWorkloads(ctx, dockerPath)
	if err != nil {
		appendWarning(out, "docker ps: "+err.Error())
		return
	}
	out.DockerContainersTruncated = more
	if len(ids) == 0 {
		return
	}
	raw, err := runCmd(ctx, dockerPath, append([]string{"inspect"}, ids...)...)
	if err != nil {
		appendWarning(out, "docker inspect: "+err.Error())
		return
	}
	var list []dockerInspectShape
	if err := json.Unmarshal(raw, &list); err != nil {
		appendWarning(out, "docker inspect JSON parse failed")
		return
	}
	for _, c := range list {
		if !c.State.Running {
			continue
		}
		out.DockerContainers = append(out.DockerContainers, buildDockerWorkload(c))
	}
	sort.SliceStable(out.DockerContainers, func(i, j int) bool {
		return out.DockerContainers[i].Name < out.DockerContainers[j].Name
	})
}

func dockerRunningIDsForWorkloads(ctx context.Context, dockerPath string) (ids []string, truncated bool, err error) {
	raw, err := runCmd(ctx, dockerPath, "ps", "-q", "--no-trunc")
	if err != nil {
		return nil, false, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(ids) >= workloadsDockerCap {
			truncated = true
			break
		}
		ids = append(ids, line)
	}
	return ids, truncated, nil
}

func buildDockerWorkload(c dockerInspectShape) payload.DockerContainerWorkload {
	name := strings.TrimPrefix(c.Name, "/")
	idShort := c.ID
	if len(idShort) > 12 {
		idShort = idShort[:12]
	}
	imageRef := strings.TrimSpace(c.Config.Image)
	if imageRef == "" {
		imageRef = strings.TrimSpace(c.Image)
	}
	tag, digest := splitImageRef(imageRef)
	w := payload.DockerContainerWorkload{
		Name:              shared.TruncateRunes(name, 256),
		ContainerID:       shared.TruncateRunes(idShort, 64),
		Image:             shared.TruncateRunes(imageRef, 512),
		ImageTag:          shared.TruncateRunes(tag, 128),
		ImageDigest:       shared.TruncateRunes(digest, 128),
		ImageTagLatest:    isLatestTag(tag),
		ImageDigestPinned: digest != "",
		State:             shared.TruncateRunes(strings.TrimSpace(c.State.Status), 32),
		StartedAt:         shared.TruncateRunes(strings.TrimSpace(c.State.StartedAt), 64),
		RestartCount:      c.RestartCount,
		User:              shared.TruncateRunes(strings.TrimSpace(c.Config.User), 64),
		EntrypointHint:    entrypointHint(c.Config.Entrypoint, c.Config.Cmd),
		NetworkMode:       shared.TruncateRunes(strings.TrimSpace(c.HostConfig.NetworkMode), 64),
	}
	if labels := filterWorkloadLabels(c.Config.Labels); len(labels) > 0 {
		w.WorkloadLabels = labels
	}
	w.WorkloadHint = deriveWorkloadHint(imageRef, w.WorkloadLabels)
	return w
}

// splitImageRef pulls out the tag ("1.27-alpine") and digest from an
// image reference string like "nginx:1.27-alpine@sha256:abcd…".
func splitImageRef(ref string) (tag, digest string) {
	if ref == "" {
		return "", ""
	}
	if idx := strings.LastIndex(ref, "@sha256:"); idx >= 0 {
		digest = ref[idx+len("@"):]
		ref = ref[:idx]
	}
	// Tag: everything after the last ":" but only in the final path segment.
	lastSlash := strings.LastIndex(ref, "/")
	tail := ref
	if lastSlash >= 0 {
		tail = ref[lastSlash+1:]
	}
	if idx := strings.LastIndex(tail, ":"); idx >= 0 {
		tag = tail[idx+1:]
	}
	return tag, digest
}

func isLatestTag(tag string) bool {
	t := strings.TrimSpace(strings.ToLower(tag))
	return t == "" || t == "latest"
}

// entrypointHint returns the binary name (first token) of entrypoint or
// cmd — enough for the UI to recognize the workload without shipping
// user-supplied flags (which can carry secrets).
func entrypointHint(entrypoint, cmd json.RawMessage) string {
	hint := firstTokenFromJSON(entrypoint)
	if hint == "" {
		hint = firstTokenFromJSON(cmd)
	}
	return shared.TruncateRunes(hint, 64)
}

func firstTokenFromJSON(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		token := strings.TrimSpace(arr[0])
		if sp := strings.IndexAny(token, " \t"); sp > 0 {
			token = token[:sp]
		}
		if slash := strings.LastIndex(token, "/"); slash >= 0 {
			token = token[slash+1:]
		}
		return token
	}
	return ""
}

func filterWorkloadLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range in {
		if !isAllowedWorkloadLabel(k) {
			continue
		}
		out[shared.TruncateRunes(k, 128)] = shared.TruncateRunes(strings.TrimSpace(v), 256)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isAllowedWorkloadLabel(key string) bool {
	for _, p := range allowedWorkloadLabelPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// deriveWorkloadHint tries to name the workload: compose service name,
// k8s app label, OCI title — else first image path segment ("nginx",
// "redis", "postgres").
func deriveWorkloadHint(imageRef string, labels map[string]string) string {
	for _, k := range []string{
		"com.docker.compose.service",
		"io.kubernetes.container.name",
		"app.kubernetes.io/name",
		"org.opencontainers.image.title",
	} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return shared.TruncateRunes(v, 96)
		}
	}
	ref := imageRef
	if idx := strings.IndexAny(ref, ":@"); idx >= 0 {
		ref = ref[:idx]
	}
	if slash := strings.LastIndex(ref, "/"); slash >= 0 {
		ref = ref[slash+1:]
	}
	return shared.TruncateRunes(ref, 96)
}

func collectCrictlWorkloads(ctx context.Context, crictlPath string, out *payload.ContainerWorkloads) {
	podsRaw, err := runCmd(ctx, crictlPath, "pods", "--output", "json")
	if err != nil {
		appendWarning(out, "crictl pods: "+err.Error())
		return
	}
	var podList crictlPodList
	if err := json.Unmarshal(podsRaw, &podList); err != nil {
		appendWarning(out, "crictl pods JSON parse failed")
		return
	}
	containersRaw, err := runCmd(ctx, crictlPath, "ps", "--output", "json", "--all")
	if err != nil {
		appendWarning(out, "crictl ps: "+err.Error())
		return
	}
	var containerList crictlContainerList
	if err := json.Unmarshal(containersRaw, &containerList); err != nil {
		appendWarning(out, "crictl ps JSON parse failed")
		return
	}
	containersByPod := map[string][]payload.KubeletContainerWorkload{}
	for _, c := range containerList.Containers {
		imageRef := c.Image.Image
		if imageRef == "" {
			imageRef = c.ImageRef
		}
		tag, digest := splitImageRef(imageRef)
		containersByPod[c.PodSandboxID] = append(containersByPod[c.PodSandboxID], payload.KubeletContainerWorkload{
			Name:              shared.TruncateRunes(c.Metadata.Name, 128),
			Image:             shared.TruncateRunes(imageRef, 512),
			ImageTag:          shared.TruncateRunes(tag, 128),
			ImageDigest:       shared.TruncateRunes(digest, 128),
			ImageTagLatest:    isLatestTag(tag),
			ImageDigestPinned: digest != "",
			RestartCount:      c.Metadata.Attempt,
			State:             shared.TruncateRunes(strings.TrimPrefix(c.State, "CONTAINER_"), 32),
		})
	}
	for _, p := range podList.Items {
		if len(out.KubeletPods) >= workloadsKubeletCap {
			out.KubeletPodsTruncated = true
			break
		}
		pod := payload.KubeletPodWorkload{
			Name:       shared.TruncateRunes(p.Metadata.Name, 256),
			Namespace:  shared.TruncateRunes(p.Metadata.Namespace, 128),
			Phase:      shared.TruncateRunes(strings.TrimPrefix(p.State, "SANDBOX_"), 32),
			CreatedAt:  shared.TruncateRunes(p.CreatedAt, 64),
			Containers: containersByPod[p.ID],
		}
		if pod.Containers == nil {
			pod.Containers = []payload.KubeletContainerWorkload{}
		}
		out.KubeletPods = append(out.KubeletPods, pod)
	}
	sort.SliceStable(out.KubeletPods, func(i, j int) bool {
		if out.KubeletPods[i].Namespace != out.KubeletPods[j].Namespace {
			return out.KubeletPods[i].Namespace < out.KubeletPods[j].Namespace
		}
		return out.KubeletPods[i].Name < out.KubeletPods[j].Name
	})
}

func runCmd(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if err := shared.ScanContextError(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func appendWarning(out *payload.ContainerWorkloads, msg string) {
	if len(out.CollectorWarnings) >= workloadsWarningCap {
		return
	}
	out.CollectorWarnings = append(out.CollectorWarnings, shared.TruncateRunes(msg, 256))
}
