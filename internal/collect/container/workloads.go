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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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
	// Docker HTTP API version we pin — 1.41 ships with Docker 20.10+, which
	// covers every supported release. Older daemons will negotiate down.
	dockerAPIVersion = "1.41"
	// Kubelet read-only port (bindings default to 0 in modern clusters but
	// many kubeadm / k3s / operator setups still expose it on localhost).
	kubeletReadOnlyPort = 10255
	kubeletDialTimeout  = 1500 * time.Millisecond
	httpCallTimeout     = 5 * time.Second
)

// dockerSocketCandidates are the standard Unix-socket paths we probe
// when `docker` CLI is not on PATH. Ordered from most common to least.
var dockerSocketCandidates = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
}

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
//
// Each engine has a CLI path and an HTTP fallback:
//
//   - Docker: `docker` CLI (preferred) → Unix socket at /var/run/docker.sock
//     or /run/docker.sock (fallback). Hosts that talk to dockerd through a
//     socket without shipping the CLI still report their workloads.
//   - Kubernetes: `crictl` CLI (preferred) → kubelet read-only HTTP on port
//     10255 (fallback). Managed-node layouts that do not install crictl
//     still report their pods when the read-only port is enabled.
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
	} else if sock := findDockerSocket(); sock != "" {
		ran = true
		collectDockerWorkloadsHTTP(subCtx, sock, out)
	}

	if path, err := exec.LookPath("crictl"); err == nil && path != "" {
		ran = true
		collectCrictlWorkloads(subCtx, path, out)
	} else if kubeletReadOnlyReachable(subCtx) {
		ran = true
		collectKubeletReadOnlyWorkloads(subCtx, out)
	}

	if !ran {
		return nil
	}
	return out
}

// findDockerSocket returns the path to a Unix socket dockerd is listening
// on, or "" when none is found. Purely filesystem-level — no handshake,
// so this is safe to call even when dockerd is not running.
func findDockerSocket() string {
	for _, p := range dockerSocketCandidates {
		if st, err := os.Stat(p); err == nil && (st.Mode()&os.ModeSocket) != 0 {
			return p
		}
	}
	return ""
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

// ─── Docker HTTP fallback (gap #2 — no `docker` CLI on PATH) ───────────

// dockerHTTPClient returns an *http.Client that talks HTTP over the Unix
// socket at ``socketPath``. The dockerd Engine API speaks HTTP 1.1 over
// that socket; the standard library handles the rest.
func dockerHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: httpCallTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: httpCallTimeout}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// dockerHTTPGet issues GET http://unix/<path> and returns the response
// body. The hostname is a placeholder — the dialer points at a Unix
// socket, ignoring hostname entirely.
func dockerHTTPGet(ctx context.Context, client *http.Client, pathAndQuery string) ([]byte, error) {
	u := fmt.Sprintf("http://unix/v%s%s", dockerAPIVersion, pathAndQuery)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker API %s returned status %d", pathAndQuery, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// dockerContainersListEntry mirrors the subset of GET /containers/json we need.
type dockerContainersListEntry struct {
	ID string `json:"Id"`
}

func collectDockerWorkloadsHTTP(ctx context.Context, socketPath string, out *payload.ContainerWorkloads) {
	client := dockerHTTPClient(socketPath)
	// GET /containers/json — running containers only by default.
	raw, err := dockerHTTPGet(ctx, client, "/containers/json")
	if err != nil {
		appendWarning(out, "docker HTTP /containers/json: "+err.Error())
		return
	}
	var listing []dockerContainersListEntry
	if err := json.Unmarshal(raw, &listing); err != nil {
		appendWarning(out, "docker HTTP list JSON parse failed")
		return
	}
	if len(listing) > workloadsDockerCap {
		listing = listing[:workloadsDockerCap]
		out.DockerContainersTruncated = true
	}
	for _, entry := range listing {
		if strings.TrimSpace(entry.ID) == "" {
			continue
		}
		// GET /containers/{id}/json — per-container inspect.
		rawOne, err := dockerHTTPGet(ctx, client, "/containers/"+url.PathEscape(entry.ID)+"/json")
		if err != nil {
			appendWarning(out, "docker HTTP inspect "+entry.ID[:12]+": "+err.Error())
			continue
		}
		var one dockerInspectShape
		if err := json.Unmarshal(rawOne, &one); err != nil {
			appendWarning(out, "docker HTTP inspect JSON parse failed for "+entry.ID[:12])
			continue
		}
		if !one.State.Running {
			continue
		}
		out.DockerContainers = append(out.DockerContainers, buildDockerWorkload(one))
	}
	sort.SliceStable(out.DockerContainers, func(i, j int) bool {
		return out.DockerContainers[i].Name < out.DockerContainers[j].Name
	})
}

// ─── Kubelet read-only HTTP fallback (gap #3 — no `crictl` on PATH) ────

// kubeletReadOnlyReachable does a cheap TCP dial to 127.0.0.1:10255 so we
// only attempt the HTTP fallback on nodes where the port is actually
// enabled. Modern clusters disable the read-only port by default, so
// silently skipping is the right default.
func kubeletReadOnlyReachable(ctx context.Context) bool {
	if err := shared.ScanContextError(ctx); err != nil {
		return false
	}
	d := net.Dialer{Timeout: kubeletDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", kubeletReadOnlyPort))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// kubeletPodsListShape mirrors the subset of the kubelet /pods endpoint
// we need. The endpoint returns a full PodList{items[]} with K8s-native
// shape (metadata/spec/status).
type kubeletPodsListShape struct {
	Items []struct {
		Metadata struct {
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Name  string `json:"name"`
				Image string `json:"image"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name         string `json:"name"`
				Image        string `json:"image"`
				ImageID      string `json:"imageID"`
				RestartCount int    `json:"restartCount"`
				Ready        bool   `json:"ready"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func collectKubeletReadOnlyWorkloads(ctx context.Context, out *payload.ContainerWorkloads) {
	client := &http.Client{Timeout: httpCallTimeout}
	u := fmt.Sprintf("http://127.0.0.1:%d/pods", kubeletReadOnlyPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		appendWarning(out, "kubelet GET /pods: "+err.Error())
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		appendWarning(out, "kubelet GET /pods: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		appendWarning(out, fmt.Sprintf("kubelet GET /pods returned status %d", resp.StatusCode))
		return
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		appendWarning(out, "kubelet GET /pods body read: "+err.Error())
		return
	}
	var list kubeletPodsListShape
	if err := json.Unmarshal(raw, &list); err != nil {
		appendWarning(out, "kubelet /pods JSON parse failed")
		return
	}
	for _, p := range list.Items {
		if len(out.KubeletPods) >= workloadsKubeletCap {
			out.KubeletPodsTruncated = true
			break
		}
		containers := make([]payload.KubeletContainerWorkload, 0, len(p.Spec.Containers))
		// status.containerStatuses is the source of truth for restart /
		// image-digest info. When it is missing (pod still pending) we
		// fall back to spec.containers for basic identity.
		statusByName := map[string]int{}
		for i, cs := range p.Status.ContainerStatuses {
			statusByName[cs.Name] = i
		}
		for _, c := range p.Spec.Containers {
			imageRef := c.Image
			restart := 0
			state := strings.ToUpper(p.Status.Phase)
			// Prefer status.image / imageID when present: the spec image is
			// often a tag reference ("nginx:1.27") while status carries the
			// resolved digest ("nginx@sha256:…").
			if i, ok := statusByName[c.Name]; ok {
				cs := p.Status.ContainerStatuses[i]
				if strings.TrimSpace(cs.Image) != "" {
					imageRef = cs.Image
				}
				restart = cs.RestartCount
				if cs.Ready {
					state = "RUNNING"
				}
				if strings.TrimSpace(cs.ImageID) != "" && !strings.Contains(imageRef, "@") {
					imageRef = imageRef + strings.TrimPrefix(cs.ImageID, "docker-pullable://")
				}
			}
			tag, digest := splitImageRef(imageRef)
			containers = append(containers, payload.KubeletContainerWorkload{
				Name:              shared.TruncateRunes(c.Name, 128),
				Image:             shared.TruncateRunes(imageRef, 512),
				ImageTag:          shared.TruncateRunes(tag, 128),
				ImageDigest:       shared.TruncateRunes(digest, 128),
				ImageTagLatest:    isLatestTag(tag),
				ImageDigestPinned: digest != "",
				RestartCount:      restart,
				State:             shared.TruncateRunes(state, 32),
			})
		}
		out.KubeletPods = append(out.KubeletPods, payload.KubeletPodWorkload{
			Name:       shared.TruncateRunes(p.Metadata.Name, 256),
			Namespace:  shared.TruncateRunes(p.Metadata.Namespace, 128),
			Phase:      shared.TruncateRunes(strings.ToUpper(p.Status.Phase), 32),
			CreatedAt:  shared.TruncateRunes(p.Metadata.CreationTimestamp, 64),
			Containers: containers,
		})
	}
	sort.SliceStable(out.KubeletPods, func(i, j int) bool {
		if out.KubeletPods[i].Namespace != out.KubeletPods[j].Namespace {
			return out.KubeletPods[i].Namespace < out.KubeletPods[j].Namespace
		}
		return out.KubeletPods[i].Name < out.KubeletPods[j].Name
	})
}
