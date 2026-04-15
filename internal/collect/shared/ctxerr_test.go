//go:build linux

package shared

import (
	"context"
	"testing"
)

func TestScanContextError_activeContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := ScanContextError(ctx); err != nil {
		t.Fatalf("expected nil error for active context, got %v", err)
	}
}

func TestScanContextError_cancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ScanContextError(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
