//go:build linux

package main

import (
	"strconv"
	"strings"
)

// versionLess returns true when ``a`` is strictly older than ``b`` using a
// dotted-numeric comparison. Non-numeric segments compare as 0 (e.g. the
// "dev" placeholder used for un-tagged local builds is older than every
// real release).
func versionLess(a, b string) bool {
	pa := splitVersion(a)
	pb := splitVersion(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va := segment(pa, i)
		vb := segment(pb, i)
		if va != vb {
			return va < vb
		}
	}
	return false
}

func splitVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

func segment(parts []int, i int) int {
	if i < len(parts) {
		return parts[i]
	}
	return 0
}
