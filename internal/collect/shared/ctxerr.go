//go:build linux

package shared

import "context"

// ScanContextError returns ctx.Err() when ctx is non-nil and done.
func ScanContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
