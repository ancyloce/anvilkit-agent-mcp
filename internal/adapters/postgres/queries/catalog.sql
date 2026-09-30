-- The private catalog and the grant barrier (DD-08 §1/§2, migration 00003).
-- Catalog and grant mutations run under the row lock of their server,
-- descriptor or grant; every decision row is append-only; the outbox
-- insert of the same transaction goes through the watermill-sql publisher.

-- name: GetServerByResourceForUpdate :one
SELECT * FROM servers WHERE tenant_id = $1 AND canonical_resource = $2 FOR UPDATE;

-- name: InsertServer :exec
INSERT INTO servers (server_id, tenant_id, canonical_resource, transport, current_revision) VALUES ($1, $2, $3, $4, 0);

-- name: SetServerRevision :exec
UPDATE servers SET current_revision = $2 WHERE server_id = $1;

-- name: GetServer :one
SELECT * FROM servers WHERE server_id = $1;

-- name: GetDescriptor :one
SELECT * FROM descriptors WHERE server_id = $1 AND revision = $2;

-- name: GetDescriptorForUpdate :one
SELECT * FROM descriptors WHERE server_id = $1 AND revision = $2 FOR UPDATE;

-- name: GetDescriptorByDigest :one
SELECT * FROM descriptors WHERE server_id = $1 AND descriptor_digest = $2;

-- name: InsertDescriptor :exec
INSERT INTO descriptors (server_id, revision, protocol_version, provenance, descriptor_digest, tools, state, command_id, request_digest,
    server_name, server_version, resources, prompts, resources_digest, prompts_digest, data_class, network_scope, licenses, issuer,
    revision_evidence, connection_ref, discovered_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22);

-- name: UpdateDescriptorState :exec
UPDATE descriptors SET state = $3, reviewer = COALESCE(sqlc.narg(reviewer), reviewer), review_id = COALESCE(sqlc.narg(review_id), review_id), updated_at = now()
WHERE server_id = $1 AND revision = $2;

-- name: ListDescriptors :many
SELECT d.* FROM descriptors d JOIN servers s ON s.server_id = d.server_id
WHERE s.tenant_id = $1 AND (sqlc.arg(state)::text = '' OR d.state = sqlc.arg(state)::text)
  AND (sqlc.arg(include_pending)::boolean OR d.state IN ('approved', 'disabled'))
  AND (d.server_id, d.revision) > (sqlc.arg(after_server)::text, sqlc.arg(after_revision)::bigint)
ORDER BY d.server_id, d.revision LIMIT sqlc.arg(page_limit);

-- name: InsertReview :exec
INSERT INTO reviews (review_id, server_id, revision, descriptor_digest, reviewer, decision, reason_code, command_id, request_digest, tenant_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetCatalogCommand :one
SELECT * FROM catalog_commands WHERE tenant_id = $1 AND command_id = $2;

-- name: InsertCatalogCommand :exec
INSERT INTO catalog_commands (tenant_id, command_id, command_kind, request_digest, server_id, revision) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetGrant :one
SELECT * FROM grants WHERE grant_id = $1;

-- name: GetGrantForUpdate :one
SELECT * FROM grants WHERE grant_id = $1 FOR UPDATE;

-- name: GetGrantByCommand :one
SELECT * FROM grants WHERE tenant_id = $1 AND command_id = $2;

-- name: InsertGrant :exec
INSERT INTO grants (grant_id, revision, tenant_id, subject_type, subject_id, server_id, descriptor_revision, descriptor_digest, methods, purpose,
    cost_cap_currency, cost_cap_amount, state, expires_at, command_id, request_digest, canonical_resource, transport, protocol_version, issuer,
    audience, resource_selectors, prompt_selectors, data_class, policy_digest, registration_command_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26);

-- name: UpdateGrantBarrier :execrows
UPDATE grants SET state = $2, control_receipt_id = $3, policy_epoch = $4, failure_code = $5, revocation_command_id = $6, fenced_at = $7,
    in_flight_calls = $8, unknown_calls = $9, control_state = $10, revoked_at = $11, updated_at = now()
WHERE grant_id = $1 AND state = sqlc.arg(expected_state);

-- name: InsertGrantDecision :exec
INSERT INTO grant_decisions (decision_id, grant_id, from_revision, to_revision, decision, decider, reason_code, command_id, request_digest, tenant_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetGrantDecisionByCommand :one
SELECT * FROM grant_decisions WHERE tenant_id = $1 AND command_id = $2 AND decision = $3;

-- name: ListGrants :many
SELECT * FROM grants
WHERE tenant_id = $1 AND (sqlc.arg(state)::text = '' OR state = sqlc.arg(state)::text)
  AND (sqlc.arg(read_all)::boolean OR subject_type = 'tenant'
       OR (subject_type = 'project' AND subject_id = sqlc.arg(project_id)::text)
       OR (subject_type = 'actor' AND subject_id = sqlc.arg(actor_id)::text))
  AND grant_id > sqlc.arg(after_grant)::text
ORDER BY grant_id LIMIT sqlc.arg(page_limit);

-- name: ListOpenBarriers :many
SELECT grant_id FROM grants WHERE state IN ('pending', 'revoking') AND updated_at <= now() - make_interval(secs => sqlc.arg(age_seconds)::float8)
ORDER BY updated_at LIMIT sqlc.arg(page_limit);

-- name: ListGrantsOfDescriptor :many
SELECT grant_id FROM grants WHERE server_id = $1 AND descriptor_revision = $2 AND state IN ('pending', 'active') ORDER BY grant_id;

-- name: ListExpiredGrants :many
SELECT grant_id FROM grants WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= $1 ORDER BY expires_at LIMIT $2;

-- name: CountOpenToolRequests :one
SELECT count(*)::bigint FROM tool_requests WHERE grant_id = $1 AND grant_revision = $2 AND state IN ('accepted', 'admitted', 'sent', 'unknown');
