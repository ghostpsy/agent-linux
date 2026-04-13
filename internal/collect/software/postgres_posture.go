//go:build linux

package software

import (
	"context"

	"github.com/ghostpsy/agent-linux/internal/collect/software/postgres"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

// CollectPostgresPosture collects PostgreSQL security posture (no SQL). listeners should be the same-scan TCP snapshot.
func CollectPostgresPosture(ctx context.Context, services []payload.ServiceEntry, listeners []payload.Listener) *payload.PostgresPosture {
	return postgres.CollectPostgresPosture(ctx, services, listeners)
}
