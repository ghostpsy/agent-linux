package state

import "testing"

func TestParseDBusMachineIDToUUID(t *testing.T) {
	u, ok := parseDBusMachineIDToUUID("03030303030303030303030303030303")
	if !ok {
		t.Fatal("expected ok")
	}
	if u.String() != "03030303-0303-0303-0303-030303030303" {
		t.Fatalf("got %s", u.String())
	}
	_, ok = parseDBusMachineIDToUUID("not-hex")
	if ok {
		t.Fatal("expected invalid")
	}
	_, ok = parseDBusMachineIDToUUID("abcd")
	if ok {
		t.Fatal("expected wrong length")
	}
}
