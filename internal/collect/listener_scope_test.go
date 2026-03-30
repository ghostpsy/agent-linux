//go:build linux

package collect

import (
	"testing"

	"ghostpsy/agent-linux/internal/payload"
)

func TestClassifyListenerExposure(t *testing.T) {
	tPub := true
	hnPub := &payload.HostNetwork{HasPublicIPv4: &tPub}
	tFalse := false
	hnPriv := &payload.HostNetwork{HasPublicIPv4: &tFalse, HasPublicIPv6: &tFalse}

	cases := []struct {
		bind       string
		hn         *payload.HostNetwork
		wantScope  string
		wantExpose string
	}{
		{"127.0.0.1:443", hnPub, bindScopeLocalhost, exposureInternal},
		{"[::1]:22", hnPub, bindScopeLocalhost, exposureInternal},
		{"192.168.1.1:80", hnPub, bindScopeLAN, exposureInternal},
		{"0.0.0.0:443", hnPub, bindScopeAllInterfaces, exposureInternet},
		{"[::]:443", hnPub, bindScopeAllInterfaces, exposureInternet},
		{"0.0.0.0:443", hnPriv, bindScopeAllInterfaces, exposureInternal},
		{"203.0.113.5:443", hnPub, bindScopeUnknown, exposureInternet},
	}
	for _, tc := range cases {
		bs, er := classifyListenerExposure(tc.bind, tc.hn)
		if bs != tc.wantScope || er != tc.wantExpose {
			t.Errorf("%q hn=%v: got scope=%q risk=%q want scope=%q risk=%q",
				tc.bind, tc.hn != nil, bs, er, tc.wantScope, tc.wantExpose)
		}
	}
}
