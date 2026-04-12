//go:build linux

package main

import "io"

// readLimited reads r until EOF or maxBytes bytes, whichever comes first.
func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxBytes))
}
