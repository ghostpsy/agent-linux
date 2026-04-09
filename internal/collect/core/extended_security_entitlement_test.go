//go:build linux

package core

import (
	"encoding/json"
	"testing"
)

func TestUAJSONIndicatesESMEnabled(t *testing.T) {
	t.Parallel()
	if uaJSONIndicatesESMEnabled([]byte(`not json`)) {
		t.Fatal("invalid json should be false")
	}
	attached := true
	st := uaLikeStatus{Attached: &attached, Services: []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{{Name: "esm-infra", Status: "enabled"}}}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !uaJSONIndicatesESMEnabled(raw) {
		t.Fatal("esm-infra enabled should be true")
	}
	st2 := uaLikeStatus{Attached: &attached, Services: []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{{Name: "livepatch", Status: "enabled"}}}
	raw2, _ := json.Marshal(st2)
	if uaJSONIndicatesESMEnabled(raw2) {
		t.Fatal("livepatch only should be false")
	}
	falseV := false
	st3 := uaLikeStatus{Attached: &falseV, Services: []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{{Name: "esm-infra", Status: "enabled"}}}
	raw3, _ := json.Marshal(st3)
	if uaJSONIndicatesESMEnabled(raw3) {
		t.Fatal("not attached should be false")
	}
}
