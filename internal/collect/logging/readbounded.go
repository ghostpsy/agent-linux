//go:build linux

package logging

import (
	"io"
	"os"
)

const maxConfigReadBytes = 96 * 1024

func readFileBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := io.LimitReader(f, maxConfigReadBytes)
	return io.ReadAll(r)
}
