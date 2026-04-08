//go:build linux

package core

import (
	"reflect"
	"testing"
)

func TestParsePPidFromProcStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status string
		want   int
		ok     bool
	}{
		{"Name:\tksoftirqd/1\nPPid:\t2\n", 2, true},
		{"PPid:\t1\n", 1, true},
		{"Name:\tbash\n", 0, false},
		{"PPid:\t\n", 0, false},
	}
	for _, tc := range cases {
		got, ok := parsePPidFromProcStatus(tc.status)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("status %q: got (%d, %v) want (%d, %v)", tc.status, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDedupeSortedInts(t *testing.T) {
	t.Parallel()
	if got := dedupeSortedInts([]int{22, 22, 22}); !reflect.DeepEqual(got, []int{22}) {
		t.Fatalf("got %v want [22]", got)
	}
	if got := dedupeSortedInts([]int{443, 80, 80}); !reflect.DeepEqual(got, []int{80, 443}) {
		t.Fatalf("got %v want [80 443]", got)
	}
	if got := dedupeSortedInts([]int{7}); !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("got %v", got)
	}
	if got := dedupeSortedInts(nil); got != nil {
		t.Fatalf("got %v want nil", got)
	}
}
