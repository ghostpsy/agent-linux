//go:build linux

package shared

import (
	"io"
	"os"
)

// DefaultConfigFileReadLimit caps typical config file reads (web server snippets, logrotate, cron, etc.).
const DefaultConfigFileReadLimit int64 = 96 << 10

// ReadFileBounded reads at most maxBytes from path (regular file open).
func ReadFileBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
