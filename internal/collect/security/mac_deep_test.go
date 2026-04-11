//go:build linux

package security

import "testing"

func TestParseAaStatusJSONCounts_profilesNested(t *testing.T) {
	raw := []byte(`{"profiles":{"enforce":40,"complain":2}}`)
	e, c, err := parseAaStatusJSONCounts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e != 40 || c != 2 {
		t.Fatalf("enforce=%d complain=%d", e, c)
	}
}

func TestParseAaStatusJSONCounts_topLevelKeys(t *testing.T) {
	raw := []byte(`{"profiles_enforce":102,"profiles_complain":8}`)
	e, c, err := parseAaStatusJSONCounts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e != 102 || c != 8 {
		t.Fatalf("enforce=%d complain=%d", e, c)
	}
}

func TestSelinuxLabelUnconfinedLike(t *testing.T) {
	if !selinuxLabelUnconfinedLike("") {
		t.Fatal("empty should match")
	}
	if !selinuxLabelUnconfinedLike("system_u:system_r:unconfined_t:s0") {
		t.Fatal("unconfined_t")
	}
	if selinuxLabelUnconfinedLike("system_u:system_r:kernel_t:s0") {
		t.Fatal("kernel_t excluded")
	}
}

func TestFirstPsZLabelField(t *testing.T) {
	got := firstPsZLabelField("system_u:system_r:sshd_t:s0  1234 ? 00:00:00 sshd")
	if got != "system_u:system_r:sshd_t:s0" {
		t.Fatalf("got %q", got)
	}
}
