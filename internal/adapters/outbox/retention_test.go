package outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/testdb"
)

// P3.7 AC5: the app role's retention deletes exactly the delivery rows past
// their bounds - the outbox rows the forwarder acknowledged, old inbox
// entries and the attempts of terminal requests - and keeps an
// unacknowledged outbox row, a recent inbox entry and an open request's
// attempts.
func TestRetainBoundsTheDeliveryTables(t *testing.T) {
	db := testdb.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const digest = "sha256:0dc7fa9db7237a2b5c96f70f59bb00f73bb86a0ca5554e91c312f9ada26e18b3"
	old := "now() - interval '10 days'"
	db.Admin(t,
		// Two old outbox rows in two transactions; the forwarder acknowledged the first.
		`INSERT INTO outbox ("uuid", created_at, payload, transaction_id) VALUES ('00000000-0000-0000-0000-000000000001', (`+old+`)::timestamp, '{}', pg_current_xact_id())`,
		`INSERT INTO outbox ("uuid", created_at, payload, transaction_id) VALUES ('00000000-0000-0000-0000-000000000002', (`+old+`)::timestamp, '{}', pg_current_xact_id())`,
		`INSERT INTO outbox_offsets (consumer_group, offset_acked, last_processed_transaction_id)
		   SELECT 'fwd', "offset", transaction_id FROM outbox WHERE "uuid" = '00000000-0000-0000-0000-000000000001'`,
		`INSERT INTO inbox (event_id, consumer, accepted_at) VALUES ('00000000-0000-0000-0000-0000000000a1', 'c', `+old+`), ('00000000-0000-0000-0000-0000000000a2', 'c', now())`,
		`INSERT INTO background_requests (task_id, generation, tenant_id, task_kind, input_digest, input, state, max_attempts, result_profile, authorization_ref, correlation_id, updated_at)
		 VALUES ('done', 1, 'tenant_a', 'mcp-catalog-refresh', '`+digest+`', '{}', 'accepted', 1, 'p', 'grant:g', 'c1', now() - interval '40 days'),
		        ('open', 1, 'tenant_a', 'mcp-catalog-refresh', '`+digest+`', '{}', 'leased', 1, 'p', 'grant:g', 'c2', now() - interval '40 days')`,
		`INSERT INTO task_attempts (task_id, generation, ordinal, worker_id, lease_until) VALUES ('done', 1, 1, 'w', now()), ('open', 1, 1, 'w', now())`,
	)
	pool := db.Pool(t)
	now := time.Now()
	pruned, err := outbox.Retain(ctx, pool, outbox.Bounds{ConsumerGroup: "fwd", OutboxBefore: now.Add(-7 * 24 * time.Hour),
		InboxBefore: now.Add(-7 * 24 * time.Hour), AttemptsBefore: now.Add(-30 * 24 * time.Hour), Batch: 100})
	require.NoError(t, err, "the app role holds DELETE on the delivery tables (mcp 00009)")
	require.Equal(t, map[string]int64{"outbox": 1, "inbox": 1, "attempts": 1}, pruned)
	var outboxLeft, inboxLeft int
	var attemptLeft string
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE "uuid" = '00000000-0000-0000-0000-000000000002'`).Scan(&outboxLeft))
	require.Equal(t, 1, outboxLeft, "the unacknowledged row stays")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM inbox`).Scan(&inboxLeft))
	require.Equal(t, 1, inboxLeft, "the recent inbox entry stays")
	require.NoError(t, pool.QueryRow(ctx, `SELECT task_id FROM task_attempts`).Scan(&attemptLeft))
	require.Equal(t, "open", attemptLeft, "an open request's attempts stay")
	// A second pass finds nothing more; the app role still deletes no business row.
	again, err := outbox.Retain(ctx, pool, outbox.Bounds{ConsumerGroup: "fwd", OutboxBefore: now, InboxBefore: now.Add(-time.Hour), AttemptsBefore: now, Batch: 100})
	require.NoError(t, err)
	require.Equal(t, map[string]int64{"outbox": 0, "inbox": 0, "attempts": 0}, again)
	_, err = pool.Exec(ctx, "DELETE FROM background_requests WHERE task_id = 'done'")
	require.ErrorContains(t, err, "permission denied")
}
