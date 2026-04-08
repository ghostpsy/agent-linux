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
