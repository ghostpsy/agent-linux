//go:build linux

package postgres

import (
	"context"
	"testing"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func TestPostgresServiceStateFromInventory(t *testing.T) {
	t.Parallel()
	services := []payload.ServiceEntry{{Name: "postgresql@16-main.service", ActiveState: "active"}}
	if s := postgresServiceState(context.Background(), services); s != "running" {
		t.Fatalf("got %q", s)
	}
}
