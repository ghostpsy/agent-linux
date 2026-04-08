package payload

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHostSSH_MarshalJSON_ErrorOnlyOmitsUserPresenceFields(t *testing.T) {
	hs := &HostSSH{Error: "No information extracted. OpenSSH effective configuration could not be read from sshd."}
	encoded, err := json.Marshal(hs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(encoded)
	if strings.Contains(s, "allow_users_present") || strings.Contains(s, "deny_users_present") {
		t.Fatalf("expected error-only host_ssh JSON to omit user presence flags, got %s", s)
	}
}

func TestHostSSH_MarshalJSON_IncludesUserPresenceWhenSet(t *testing.T) {
	yes, no := true, false
	hs := &HostSSH{AllowUsersPresent: &yes, DenyUsersPresent: &no}
	encoded, err := json.Marshal(hs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(encoded)
	if !strings.Contains(s, `"allow_users_present":true`) || !strings.Contains(s, `"deny_users_present":false`) {
		t.Fatalf("expected both user presence flags in JSON, got %s", s)
	}
}
