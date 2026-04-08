//go:build linux

package software

import (
	"encoding/json"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestApplyDaemonJSONTlsMaterial(t *testing.T) {
	raw := []byte(`{"tlscacert":"/etc/docker/ca.pem","tlsverify":true}`)
	var d dockerDaemonJSONKeys
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	out := &payload.DockerHostFingerprint{}
	applyDaemonJSON(out, &d)
	if out.TlsInDaemonJSON == nil || !*out.TlsInDaemonJSON {
		t.Fatal("expected tls_in_daemon_json true from tlscacert path")
	}
	if out.TlsVerifyInDaemonJSON == nil || !*out.TlsVerifyInDaemonJSON {
		t.Fatal("expected tlsverify true")
	}
}

func TestInferRootlessFromSock(t *testing.T) {
	if got := inferRootlessFromSock("/run/user/1000/docker.sock"); got != "likely_rootless" {
		t.Fatalf("got %q", got)
	}
	if got := inferRootlessFromSock("/var/run/docker.sock"); got != "unknown" {
		t.Fatalf("got %q", got)
	}
}

func TestParseDockerInfoJSONRootless(t *testing.T) {
	raw := `{"Containers":3,"SecurityOptions":["name=seccomp","name=cgroupns"],"Rootless":true}`
	var info dockerInfoJSON
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatal(err)
	}
	if info.Containers != 3 || !info.Rootless {
		t.Fatalf("%+v", info)
	}
}
