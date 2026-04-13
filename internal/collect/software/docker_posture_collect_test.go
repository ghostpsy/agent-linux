//go:build linux

package software

import "testing"

func TestImageTagIsLatest(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"nginx:latest", true},
		{"nginx", true},
		{"repo/nginx", true},
		{"host:5000/nginx:latest", true},
		{"host:5000/nginx:1.25", false},
		{"nginx:stable", false},
		{"repo/nginx@sha256:abc", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := imageTagIsLatest(tc.ref); got != tc.want {
			t.Fatalf("imageTagIsLatest(%q)=%v want %v", tc.ref, got, tc.want)
		}
	}
}

func TestParseDockerdArgsTCP(t *testing.T) {
	args := []string{"/usr/bin/dockerd", "-H", "tcp://0.0.0.0:2375", "--config-file", "/etc/docker/d.json"}
	tcp, tls, rootless, cf := parseDockerdArgs(args)
	if len(tcp) != 1 || tcp[0] != "0.0.0.0:2375" {
		t.Fatalf("tcp hosts: %#v", tcp)
	}
	if tls || rootless {
		t.Fatalf("unexpected tls/rootless")
	}
	if cf != "/etc/docker/d.json" {
		t.Fatalf("config file: %q", cf)
	}
}

func TestIsSensitiveHostPath(t *testing.T) {
	dr := "/var/lib/docker"
	if !isSensitiveHostPath("/etc/shadow", dr) {
		t.Fatal("etc")
	}
	if !isSensitiveHostPath("/var/lib/docker/volumes/x", dr) {
		t.Fatal("docker data")
	}
	if isSensitiveHostPath("/var/lib/other", dr) {
		t.Fatal("other var lib")
	}
}

func TestOverlayEncrypted(t *testing.T) {
	if !overlayEncrypted(map[string]string{"encrypted": "true"}) {
		t.Fatal("true")
	}
	if overlayEncrypted(map[string]string{"encrypted": "false"}) {
		t.Fatal("false")
	}
	if overlayEncrypted(nil) {
		t.Fatal("nil")
	}
}
