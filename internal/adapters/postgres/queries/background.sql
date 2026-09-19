-- Durable background requests of the MCP owner (DD-09 §1, migration 00002).
-- Every mutation runs under the row lock of the generation; the outbox
-- insert of the same transaction goes through the watermill-sql publisher.

-- name: GetRequestForUpdate :one
SELECT * FROM background_requests WHERE task_id = $1 AND generation = $2 FOR UPDATE;

-- name: GetRequest :one
SELECT * FROM background_requests WHERE task_id = $1 AND generation = $2;

-- name: GetLatestRequestForUpdate :one
SELECT * FROM background_requests WHERE task_id = $1 ORDER BY generation DESC LIMIT 1 FOR UPDATE;

-- name: GetLatestRequest :one
SELECT * FROM background_requests WHERE task_id = $1 ORDER BY generation DESC LIMIT 1;

-- name: InsertRequest :exec
INSERT INTO background_requests (
    task_id, generation, tenant_id, task_kind, input_digest, input, state, attempt_count, max_attempts,
    result_profile, effects, dispatch_id, authorization_ref, revision, correlation_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10, $11, $12, 1, $13);

-- name: UpdateRequest :execrows
UPDATE background_requests SET
    state = $3, worker_id = $4, lease_until = $5, attempt_count = $6, retry_at = $7,
    result_ref = $8, result_digest = $9, failure_code = $10, revision = $11, completed_at = $12, updated_at = now()
WHERE task_id = $1 AND generation = $2 AND revision = sqlc.arg(expected_revision);

-- name: ListAttempts :many
SELECT * FROM task_attempts WHERE task_id = $1 AND generation = $2 ORDER BY ordinal;

-- name: InsertAttempt :exec
INSERT INTO task_attempts (task_id, generation, ordinal, worker_id, leased_at, lease_until) VALUES ($1, $2, $3, $4, $5, $6);

-- name: SetAttemptOutcome :exec
UPDATE task_attempts SET outcome = $4, submitted_at = $5 WHERE task_id = $1 AND generation = $2 AND ordinal = $3;

-- name: ListExpiredLeases :many
SELECT task_id, generation FROM background_requests WHERE state = 'leased' AND lease_until < $1 ORDER BY lease_until LIMIT $2;

-- name: GetGrantState :one
SELECT tenant_id, state, expires_at FROM grants WHERE grant_id = $1 FOR SHARE;

-- name: CountRequestsByState :many
SELECT state, count(*) AS n FROM background_requests GROUP BY state;

-- name: CountOverdueRetries :one
SELECT count(*) FROM background_requests WHERE state = 'retry_scheduled' AND retry_at < $1;

-- name: OldestUnforwardedSeconds :one
SELECT COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at))), 0)::float8 AS seconds
FROM outbox
WHERE (transaction_id, "offset") > (
    SELECT COALESCE(max(last_processed_transaction_id), '0'::xid8), COALESCE(max(offset_acked), 0)
    FROM outbox_offsets WHERE consumer_group = $1
);

-- name: CountInboxDuplicates :one
SELECT count(*) FROM inbox WHERE consumer = $1 AND outcome LIKE 'duplicate%';

-- name: CanonicalJSON :one
SELECT $1::jsonb::text AS canonical;
