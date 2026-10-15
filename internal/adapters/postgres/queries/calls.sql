-- Tool requests (P19). Every state change is a guarded update of the row
-- under its lock; the send marker is committed before the single send.

-- name: GetToolRequest :one
SELECT * FROM tool_requests WHERE call_id = $1;

-- name: GetToolRequestForUpdate :one
SELECT * FROM tool_requests WHERE call_id = $1 FOR UPDATE;

-- name: GetToolRequestByCommand :one
SELECT * FROM tool_requests WHERE tenant_id = $1 AND command_id = $2;

-- name: GetGrantForShare :one
SELECT * FROM grants WHERE grant_id = $1 FOR SHARE;

-- name: HasUnknownToolRequest :one
SELECT EXISTS (SELECT 1 FROM tool_requests WHERE tenant_id = $1 AND server_id = $2 AND state = 'unknown');

-- name: InsertToolRequest :exec
INSERT INTO tool_requests (call_id, tenant_id, grant_id, grant_revision, server_id, descriptor_revision, method, argument_ref, argument_digest,
    operation_id, attempt_id, state, command_id, request_digest, deadline, instance_id, execution_epoch, arguments, descriptor_digest,
    protocol_version, transport, route, side_effecting, exposure_currency, exposure_amount)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'accepted', $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24);

-- name: SetToolRequestAdmission :execrows
UPDATE tool_requests SET state = $2, control_dispatch_id = $3, failure_code = $4, updated_at = now()
WHERE call_id = $1 AND state = 'accepted';

-- name: SetToolRequestMarker :execrows
UPDATE tool_requests SET state = 'sent', send_marker_at = now(), updated_at = now()
WHERE call_id = $1 AND state = 'admitted' AND send_marker_at IS NULL;

-- name: SetToolRequestOutcome :execrows
UPDATE tool_requests SET state = $2, failure_code = $3, result = $4, result_digest = $5, result_ref = $6, native_evidence = $7, usage_units = $8,
    updated_at = now()
WHERE call_id = $1 AND state = ANY(sqlc.arg(expected)::text[]);

-- name: SetToolRequestObserved :exec
UPDATE tool_requests SET observed_at = now(), observation_sequence = observation_sequence + 1, updated_at = now()
WHERE call_id = $1 AND observation_sequence = $2;

-- name: ListOpenToolRequests :many
-- One page of the open calls, keyset-ordered by (updated_at, call_id) after
-- the cursor: a pass walks every open row in pages, so rows that cannot be
-- advanced (UNKNOWN until Control resolves them) never hide the rows behind
-- them. A marked call whose sender died is found by its marker age (the
-- send bound), every other open row by its age (reconcile_age).
SELECT * FROM tool_requests
WHERE ((state IN ('accepted', 'admitted', 'unknown') OR (observed_at IS NULL AND control_dispatch_id IS NOT NULL AND state IN ('succeeded', 'failed', 'canceled')))
        AND updated_at < now() - make_interval(secs => sqlc.arg(age_seconds)::float8)
     OR (state = 'sent' AND send_marker_at < now() - make_interval(secs => sqlc.arg(sent_age_seconds)::float8)))
  AND (updated_at, call_id) > (sqlc.arg(after_at)::timestamptz, sqlc.arg(after_id)::text)
ORDER BY updated_at, call_id LIMIT $1;

-- name: UnknownToolCallStats :one
-- P3.6: the UNKNOWN tool calls for the operator's gauges: their number, the
-- (tenant, server) pairs they restrict (RECOVERY_RESTRICTED) and the age of
-- the oldest since it last changed. Served by tool_requests_unknown_idx.
SELECT count(*)::bigint AS calls,
       count(DISTINCT (tenant_id, server_id))::bigint AS restricted_servers,
       coalesce(extract(epoch FROM now() - min(updated_at)), 0)::float8 AS oldest_seconds
FROM tool_requests WHERE state = 'unknown';
