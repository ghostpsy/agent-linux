//go:build linux

package collect

import (
	"reflect"
	"testing"
)

func TestParseServiceStatusAll_debianStyle(t *testing.T) {
	const sample = ` [ + ]  acpid
 [ - ]  apache2
 [ ? ]  cryptdisks
 [ + ]  cron
`
	got := parseServiceStatusAll([]byte(sample))
	want := []string{"acpid", "cron"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseServiceStatusAll_noLeadingSpace(t *testing.T) {
	const sample = `[ + ]  ssh
`
	got := parseServiceStatusAll([]byte(sample))
	if len(got) != 1 || got[0] != "ssh" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseChkconfigList_sysvRows(t *testing.T) {
	const sample = `
Note: This output shows SysV services only and does not include native
      systemd services.

crond          	0:off	1:off	2:on	3:on	4:on	5:on	6:off
sshd           	0:off	1:off	2:on	3:on	4:on	5:on	6:off
netconsole     	0:off	1:off	2:off	3:off	4:off	5:off	6:off
`
	got := parseChkconfigList([]byte(sample))
	if len(got) != 3 {
		t.Fatalf("got len=%d entries=%#v", len(got), got)
	}
	if got[0].Name != "crond" || got[0].Manager != "sysvinit" || got[0].Enabled == nil || !*got[0].Enabled {
		t.Fatalf("unexpected crond row: %#v", got[0])
	}
	if got[2].Name != "netconsole" || got[2].Enabled == nil || *got[2].Enabled {
		t.Fatalf("unexpected netconsole row: %#v", got[2])
	}
}
