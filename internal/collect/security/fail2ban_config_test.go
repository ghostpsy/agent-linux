//go:build linux

package security

import (
	"reflect"
	"testing"
)

func TestMergeFail2banIniBodies_enabledJailsAndDefault(t *testing.T) {
	files := []fail2banNamedConfig{
		{Path: "jail.conf", Body: []byte(`
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = false

[nginx-http-auth]
enabled = true
`)},
		{Path: "jail.d/override.conf", Body: []byte(`
[sshd]
enabled = true
`)},
	}
	got := mergeFail2banIniBodies(files)
	if got.DefaultBantime != "10m" || got.DefaultFindtime != "10m" || got.DefaultMaxRetry != "5" {
		t.Fatalf("defaults: %#v", got)
	}
	if got.JailSectionCountHint != 2 {
		t.Fatalf("jail count: %d", got.JailSectionCountHint)
	}
	want := []string{"nginx-http-auth", "sshd"}
	if !reflect.DeepEqual(got.EnabledJails, want) {
		t.Fatalf("enabled jails: %#v", got.EnabledJails)
	}
}

func TestMergeFail2banIniBodies_numericEnabled(t *testing.T) {
	files := []fail2banNamedConfig{
		{Path: "a.conf", Body: []byte(`
[testjail]
enabled = 1
`)},
	}
	got := mergeFail2banIniBodies(files)
	if len(got.EnabledJails) != 1 || got.EnabledJails[0] != "testjail" {
		t.Fatalf("%#v", got.EnabledJails)
	}
}

func TestMergeFail2banIniBodies_inlineComment(t *testing.T) {
	files := []fail2banNamedConfig{
		{Path: "a.conf", Body: []byte(`
[myjail]
enabled = true  # comment
`)},
	}
	got := mergeFail2banIniBodies(files)
	if len(got.EnabledJails) != 1 || got.EnabledJails[0] != "myjail" {
		t.Fatalf("%#v", got.EnabledJails)
	}
}

func TestMergeFail2banIniBodies_capsEnabledJails(t *testing.T) {
	var bodies []fail2banNamedConfig
	for i := range 60 {
		name := byte('a' + (i % 26))
		sec := string(name) + string(rune('0'+i/26))
		bodies = append(bodies, fail2banNamedConfig{
			Path: "x.conf",
			Body: []byte("[" + sec + "]\nenabled = true\n"),
		})
	}
	got := mergeFail2banIniBodies(bodies)
	if len(got.EnabledJails) != fail2banMaxEnabledJails {
		t.Fatalf("expected cap %d, got %d", fail2banMaxEnabledJails, len(got.EnabledJails))
	}
}
