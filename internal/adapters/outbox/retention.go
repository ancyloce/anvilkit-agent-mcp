package outbox

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Bounds of one retention pass (P3.7): rows older than each bound go, at
// most Batch rows per table.
type Bounds struct {
	ConsumerGroup  string
	OutboxBefore   time.Time
	InboxBefore    time.Time
	AttemptsBefore time.Time
	Batch          int
}

// Retain deletes, a bounded batch per table, the outbox rows the consumer
// group acknowledged (at or before its position) older than OutboxBefore,
// the inbox entries accepted before InboxBefore, and the attempts of
// terminal requests last changed before AttemptsBefore; it answers the
// count per table. Unacknowledged outbox rows, open requests' attempts and
// every business row are never touched. created_at of the outbox is
// watermill's timestamp without time zone written in the session's zone, so
// that bound is compared in that zone.
func Retain(ctx context.Context, pool *pgxpool.Pool, b Bounds) (map[string]int64, error) {
	out := map[string]int64{}
	for _, step := range []struct {
		table string
		sql   string
		args  []any
	}{
		{"outbox", `DELETE FROM outbox WHERE ctid IN (
			SELECT o.ctid FROM outbox o JOIN outbox_offsets f ON f.consumer_group = $1
			WHERE (o.transaction_id < f.last_processed_transaction_id
			       OR (o.transaction_id = f.last_processed_transaction_id AND o."offset" <= COALESCE(f.offset_acked, 0)))
			  AND o.created_at < ($2::timestamptz AT TIME ZONE current_setting('TimeZone')) LIMIT $3)`, []any{b.ConsumerGroup, b.OutboxBefore, b.Batch}},
		{"inbox", `DELETE FROM inbox WHERE ctid IN (SELECT ctid FROM inbox WHERE accepted_at < $1 LIMIT $2)`, []any{b.InboxBefore, b.Batch}},
		{"attempts", `DELETE FROM task_attempts WHERE ctid IN (
			SELECT a.ctid FROM task_attempts a JOIN background_requests r ON r.task_id = a.task_id AND r.generation = a.generation
			WHERE r.state IN ('accepted', 'dead', 'stale', 'canceled') AND r.updated_at < $1 LIMIT $2)`, []any{b.AttemptsBefore, b.Batch}},
	} {
		tag, err := pool.Exec(ctx, step.sql, step.args...)
		if err != nil {
			return out, err
		}
		out[step.table] = tag.RowsAffected()
	}
	return out, nil
}
