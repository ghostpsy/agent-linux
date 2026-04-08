package payload

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSudoersAudit_MarshalJSON_ErrorOnlyEmitsError(t *testing.T) {
	s := &SudoersAudit{Error: "sudoers could not be read"}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(encoded)
	if strings.Contains(raw, "nopasswd_mention_count") || strings.Contains(raw, "defaults_requiretty_present") {
		t.Fatalf("expected error-only sudoers_audit JSON to omit counters and flags, got %s", raw)
	}
	if !strings.Contains(raw, `"error":"sudoers could not be read"`) {
		t.Fatalf("expected error field, got %s", raw)
	}
}

func TestSudoersAudit_MarshalJSON_SuccessIncludesZeros(t *testing.T) {
	s := &SudoersAudit{
		FilesScanned:                     []string{"/etc/sudoers"},
		NopasswdMentionCount:             0,
		AllAllPatternCount:               0,
		WildcardRiskLineCount:            0,
		IncludedirCount:                  0,
		DefaultsRequirettyPresent:        false,
		DefaultsUsePtyPresent:            false,
		DefaultsVisiblepwInvertedPresent: false,
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(encoded)
	if !strings.Contains(raw, `"nopasswd_mention_count":0`) || !strings.Contains(raw, `"defaults_requiretty_present":false`) {
		t.Fatalf("expected counters and flags in success JSON, got %s", raw)
	}
}
