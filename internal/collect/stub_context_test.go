//go:build linux

package collect

import (
	"context"
	"errors"
	"testing"
)

func TestStubWithObserver_AlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := StubWithObserver(ctx, "machine-uuid-test", 1, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
