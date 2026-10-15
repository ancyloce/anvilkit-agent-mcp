package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MinimumSchemaVersion is the lowest anvilkit_mcp migration version this
// binary's queries need (00009_delivery_retention: the retention loop's
// DELETE grants). The migrations are applied by the parent's migration Job
// (MIG-02); the binary does not embed them,
// so the minimum is declared here and raised with every migration a query
// starts to depend on. A schema ahead of it is accepted: the next
// release's expand migration may be applied while this image still serves.
const MinimumSchemaVersion int64 = 9

// schemaVerdict names the version pair when the applied schema is behind
// the binary's minimum.
func schemaVerdict(applied, minimum int64) error {
	if applied < minimum {
		return fmt.Errorf("schema at version %d, the binary needs at least %d", applied, minimum)
	}
	return nil
}

// checkSchema reads the applied version of the domain's own migrations
// (goose_db_version; the development fixture set keeps its own table).
func checkSchema(ctx context.Context, pool *pgxpool.Pool, minimum int64) error {
	var applied int64
	if err := pool.QueryRow(ctx, "SELECT coalesce(max(version_id), 0) FROM goose_db_version WHERE is_applied").Scan(&applied); err != nil {
		return fmt.Errorf("schema version unreadable: %w", err)
	}
	return schemaVerdict(applied, minimum)
}

// watchSchema withholds readiness while the schema is behind the minimum
// and checks again every interval until it holds (P3.1 AC4): the replica
// becomes ready once the migration Job has run, without a restart. The
// first failure and every change of the version pair are logged.
func watchSchema(ctx context.Context, h *Health, pool func() *pgxpool.Pool, minimum int64, interval time.Duration, log *slog.Logger) {
	last := ""
	for {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := checkSchema(cctx, pool(), minimum)
		cancel()
		if err == nil {
			h.setSchema("")
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err.Error() != last {
			log.Error("schema check failed; the replica stays not ready", "error", err)
			last = err.Error()
		}
		h.setSchema(err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
