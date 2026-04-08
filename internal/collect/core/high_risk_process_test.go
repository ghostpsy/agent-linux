//go:build linux

package core

import (
	"reflect"
	"testing"
)

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
