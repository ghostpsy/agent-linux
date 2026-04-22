//go:build linux

package container

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeStubBin writes a shell script to dir and returns its path. The
// script routes its positional args via a per-arg case statement to
// dispatched output files, so we can emulate "docker ps -q", "docker
// inspect ...", "crictl pods --output json", etc. with tiny fixture
// files.
func writeStubBin(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
	return path
}

// prependPATH inserts dir at the front of PATH so exec.LookPath picks
// up our stub binaries before the real ones.
func prependPATH(t *testing.T, dir string) func() {
	t.Helper()
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+orig); err != nil {
		t.Fatalf("setenv PATH: %v", err)
	}
	return func() { _ = os.Setenv("PATH", orig) }
}

// dockerStubScript emits two running container ids for `docker ps -q`
// and a two-entry inspect JSON for `docker inspect`. Anything else
// exits 1 so the collector's error path is also exercised when needed.
const dockerStubScript = `#!/bin/sh
case "$1" in
  ps)
    printf '1111111111111111111111111111111111111111111111111111111111111111\n'
    printf '2222222222222222222222222222222222222222222222222222222222222222\n'
    ;;
  inspect)
    cat <<'EOF'
[
  {
    "Id": "1111111111111111111111111111111111111111111111111111111111111111",
    "Name": "/web-1",
    "RestartCount": 0,
    "State": {"Status": "running", "Running": true, "StartedAt": "2026-04-01T00:00:00Z"},
    "Image": "sha256:deadbeef",
    "Config": {
      "Image": "nginx:1.27@sha256:abcd",
      "User": "nginx",
      "Entrypoint": ["/docker-entrypoint.sh"],
      "Cmd": ["nginx", "-g", "daemon off;"],
      "Labels": {
        "com.docker.compose.service": "web",
        "com.docker.compose.project": "myapp",
        "DATABASE_URL": "postgres://user:SECRET@db/app",
        "org.opencontainers.image.title": "My Web",
        "MY_OP_NOTES": "do not ship this"
      }
    },
    "HostConfig": {"NetworkMode": "bridge"}
  },
  {
    "Id": "2222222222222222222222222222222222222222222222222222222222222222",
    "Name": "/redis",
    "RestartCount": 3,
    "State": {"Status": "running", "Running": true, "StartedAt": "2026-04-01T00:00:00Z"},
    "Image": "",
    "Config": {
      "Image": "redis:latest",
      "User": "",
      "Entrypoint": null,
      "Cmd": ["redis-server"],
      "Labels": null
    },
    "HostConfig": {"NetworkMode": "bridge"}
  }
]
EOF
    ;;
  *) exit 1 ;;
esac
`

// crictlStubScript returns one pod with two containers.
const crictlStubScript = `#!/bin/sh
if [ "$1" = "pods" ]; then
  cat <<'EOF'
{"items":[{"id":"pod-abc","metadata":{"name":"app-5df","namespace":"default"},"state":"SANDBOX_READY","createdAt":"2026-04-01T00:00:00Z"}]}
EOF
  exit 0
fi
if [ "$1" = "ps" ]; then
  cat <<'EOF'
{"containers":[
  {"id":"c1","podSandboxId":"pod-abc","metadata":{"name":"app","attempt":2},"image":{"image":"ghcr.io/acme/app:1.2.0@sha256:beefcafe"},"imageRef":"","state":"CONTAINER_RUNNING"},
  {"id":"c2","podSandboxId":"pod-abc","metadata":{"name":"sidecar","attempt":0},"image":{"image":"busybox:latest"},"imageRef":"","state":"CONTAINER_RUNNING"}
]}
EOF
  exit 0
fi
exit 1
`

func TestCollect_NeitherEngineReturnsNil(t *testing.T) {
	dir := t.TempDir()
	// Empty PATH so neither docker nor crictl is found.
	defer prependPATH(t, dir)()

	if got := CollectContainerWorkloads(context.Background()); got != nil {
		t.Fatalf("expected nil when neither docker nor crictl is present, got: %+v", got)
	}
}

func TestCollect_DockerOnly(t *testing.T) {
	dir := t.TempDir()
	writeStubBin(t, dir, "docker", dockerStubScript)
	defer prependPATH(t, dir)()

	out := CollectContainerWorkloads(context.Background())
	if out == nil {
		t.Fatal("expected non-nil workloads when docker is present")
	}
	if len(out.DockerContainers) != 2 {
		t.Fatalf("expected 2 docker containers, got %d (%+v)", len(out.DockerContainers), out.DockerContainers)
	}
	if len(out.KubeletPods) != 0 {
		t.Fatalf("expected empty kubelet pods, got %d", len(out.KubeletPods))
	}

	// Alphabetical sort: redis before web-1.
	if out.DockerContainers[0].Name != "redis" || out.DockerContainers[1].Name != "web-1" {
		t.Fatalf("expected sorted names [redis, web-1], got [%s, %s]",
			out.DockerContainers[0].Name, out.DockerContainers[1].Name)
	}

	redis := out.DockerContainers[0]
	if !redis.ImageTagLatest || redis.ImageDigestPinned {
		t.Fatalf("redis should be latest tag, unpinned: %+v", redis)
	}
	if redis.RestartCount != 3 {
		t.Fatalf("redis restart count = %d, want 3", redis.RestartCount)
	}
	if redis.EntrypointHint != "redis-server" {
		t.Fatalf("redis entrypoint hint = %q, want 'redis-server'", redis.EntrypointHint)
	}

	web := out.DockerContainers[1]
	if web.ImageTagLatest {
		t.Fatalf("web image tag should not be 'latest': %q", web.ImageTag)
	}
	if !web.ImageDigestPinned {
		t.Fatalf("web image should be digest-pinned")
	}
	if web.WorkloadHint != "web" {
		t.Fatalf("web workload hint should come from compose service label, got %q", web.WorkloadHint)
	}
	// Allow-listed compose + OCI labels stay; arbitrary user labels (DATABASE_URL,
	// MY_OP_NOTES) must be dropped to avoid secret leak.
	if _, ok := web.WorkloadLabels["DATABASE_URL"]; ok {
		t.Fatalf("DATABASE_URL label must be dropped; got %+v", web.WorkloadLabels)
	}
	if _, ok := web.WorkloadLabels["MY_OP_NOTES"]; ok {
		t.Fatalf("MY_OP_NOTES label must be dropped; got %+v", web.WorkloadLabels)
	}
	if web.WorkloadLabels["com.docker.compose.service"] != "web" {
		t.Fatalf("expected compose.service label retained, got %+v", web.WorkloadLabels)
	}
	// Entrypoint hint should be the basename of the entrypoint — not the full
	// arg list with flags.
	if web.EntrypointHint != "docker-entrypoint.sh" {
		t.Fatalf("web entrypoint hint = %q, want 'docker-entrypoint.sh'", web.EntrypointHint)
	}
}

func TestCollect_CrictlOnly(t *testing.T) {
	dir := t.TempDir()
	writeStubBin(t, dir, "crictl", crictlStubScript)
	defer prependPATH(t, dir)()

	out := CollectContainerWorkloads(context.Background())
	if out == nil {
		t.Fatal("expected non-nil workloads when crictl is present")
	}
	if len(out.DockerContainers) != 0 {
		t.Fatalf("expected empty docker containers, got %d", len(out.DockerContainers))
	}
	if len(out.KubeletPods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(out.KubeletPods))
	}
	pod := out.KubeletPods[0]
	if pod.Name != "app-5df" || pod.Namespace != "default" {
		t.Fatalf("unexpected pod identity: %+v", pod)
	}
	if len(pod.Containers) != 2 {
		t.Fatalf("expected 2 containers in pod, got %d", len(pod.Containers))
	}
	// busybox:latest is latest-tagged and unpinned.
	sidecar := pod.Containers[1]
	if sidecar.Image != "busybox:latest" || !sidecar.ImageTagLatest || sidecar.ImageDigestPinned {
		t.Fatalf("sidecar expected busybox:latest unpinned, got %+v", sidecar)
	}
	app := pod.Containers[0]
	if !app.ImageDigestPinned || app.ImageTag != "1.2.0" {
		t.Fatalf("app expected pinned 1.2.0 tag, got %+v", app)
	}
	if app.RestartCount != 2 {
		t.Fatalf("app restart count = %d, want 2 (from attempt)", app.RestartCount)
	}
}

func TestCollect_BothEngines(t *testing.T) {
	dir := t.TempDir()
	writeStubBin(t, dir, "docker", dockerStubScript)
	writeStubBin(t, dir, "crictl", crictlStubScript)
	defer prependPATH(t, dir)()

	out := CollectContainerWorkloads(context.Background())
	if out == nil {
		t.Fatal("expected non-nil workloads when both engines are present")
	}
	if len(out.DockerContainers) != 2 {
		t.Fatalf("expected 2 docker containers, got %d", len(out.DockerContainers))
	}
	if len(out.KubeletPods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(out.KubeletPods))
	}
	// Round-trip the output through JSON to make sure the shape is ingest-safe.
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
}

// ── splitImageRef / helpers ─────────────────────────────────────────

func TestSplitImageRef(t *testing.T) {
	cases := []struct {
		in, wantTag, wantDigest string
	}{
		{"nginx:1.27-alpine", "1.27-alpine", ""},
		{"nginx:1.27@sha256:abcd", "1.27", "sha256:abcd"},
		{"ghcr.io/acme/app:v1.2.0", "v1.2.0", ""},
		{"registry.example.com:5000/app:1.0", "1.0", ""},
		{"redis", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		tag, digest := splitImageRef(c.in)
		if tag != c.wantTag || digest != c.wantDigest {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", c.in, tag, digest, c.wantTag, c.wantDigest)
		}
	}
}

func TestIsLatestTag(t *testing.T) {
	cases := map[string]bool{"": true, "latest": true, "LATEST": true, "1.27": false, "v2": false}
	for tag, want := range cases {
		if got := isLatestTag(tag); got != want {
			t.Errorf("isLatestTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

func TestIsAllowedWorkloadLabel_RejectsArbitraryUserLabels(t *testing.T) {
	allowed := []string{
		"com.docker.compose.service",
		"com.docker.compose.project",
		"io.kubernetes.container.name",
		"app.kubernetes.io/name",
		"org.opencontainers.image.title",
		"org.opencontainers.image.version",
	}
	for _, k := range allowed {
		if !isAllowedWorkloadLabel(k) {
			t.Errorf("expected %q to be allowed", k)
		}
	}
	for _, k := range []string{
		"DATABASE_URL",
		"MY_SECRET_TOKEN",
		"custom.ops.note",
		"maintainer",
	} {
		if isAllowedWorkloadLabel(k) {
			t.Errorf("expected %q to be rejected (potential user-provided data)", k)
		}
	}
	// Sanity: no empty string / whitespace acceptance.
	if isAllowedWorkloadLabel("") || isAllowedWorkloadLabel(" ") {
		t.Error("empty / whitespace labels must not be allowed")
	}
}
