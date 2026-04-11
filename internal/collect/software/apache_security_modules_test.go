//go:build linux

package software

import "testing"

func TestIsSecurityRelevantApacheModule(t *testing.T) {
	t.Parallel()
	if !isSecurityRelevantApacheModule("ssl_module") {
		t.Fatal("ssl_module should match")
	}
	if !isSecurityRelevantApacheModule("security2_module") {
		t.Fatal("security2_module should match")
	}
	if !isSecurityRelevantApacheModule("php8.2_module") {
		t.Fatal("php* _module should match")
	}
	if isSecurityRelevantApacheModule("auth_basic_module") {
		t.Fatal("auth_basic_module should not match")
	}
	if isSecurityRelevantApacheModule("") {
		t.Fatal("empty should not match")
	}
}
