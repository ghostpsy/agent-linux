//go:build linux

package collect

import (
	"testing"

	"github.com/google/nftables"
)

func TestIsIptablesParityFilterTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tab  *nftables.Table
		want bool
	}{
		{"nil", nil, false},
		{"wrong name", &nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4}, false},
		{"ip filter", &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}, true},
		{"ip6 filter", &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv6}, true},
		{"inet filter", &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}, true},
		{"bridge filter", &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isIptablesParityFilterTable(tc.tab); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
