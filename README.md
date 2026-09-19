# anvilkit-agent-mcp

The MCP service of the AnvilKit Agent platform (architecture V4.0, [DD-08](https://github.com/ancyloce/anvilkit-services/blob/main/docs/architecture/mcp.md), [DD-09](https://github.com/ancyloce/anvilkit-services/blob/main/docs/architecture/platform.md#async-config)). Go, grpc-go, Fx, pgx/sqlc, koanf, watermill.

**Implemented (P14, durable background work):** the owner side of `anvilkit.mcp.v1.BackgroundTaskService` — `ClaimTask`, `HeartbeatTask`, `SubmitTaskResult`, `GetTask` — over the `background_requests`/`task_attempts` tables of migration `00002` (still applied by the parent repository's migration Job, `jobs/migration`), the transactional outbox of the pinned watermill-sql PostgreSQL adapter bound to the same `pgx.Tx` as every domain write, the in-process watermill forwarder to NATS JetStream, the lease sweeper with the Control original-dispatch query for external-effect leases, cancellation, the immutable configuration generations with secret rotation (a new pool built and probed off-path, then swapped, then the old one drained) and the bounded Fx lifecycle. The catalog, grants and tool calls (P18/P19) are not implemented; the `local-check` task kind is the DEVELOPMENT_ONLY fixture of the background lane.

## Layout

- `cmd/anvilkit-agent-mcp` — the Fx entry point; `local-check request|cancel|get` are the DEVELOPMENT_ONLY owner entry points that create, cancel and read fixture requests through the same application code (no public create RPC exists).
- `internal/config` — koanf generations: defaults < `config.yaml` < validated Apollo snapshot < allowlisted `ANVILKIT_MCP_*` environment; `database.url` (or `database.url_file`) is the only secret.
- `internal/domain` — the request state machine (pending, leased, result_submitted, accepted, retry_scheduled, dead, stale, canceled), claim/heartbeat/submit/cancel/expire decisions, the event envelopes.
- `internal/application` — one transaction per command: decision under the row lock, attempt record, CAS update, outbox event; the lease sweeper; metrics.
- `internal/adapters/postgres` — pgx store and sqlc queries (`sqlc.yaml`, `tools/sqlc.sh --check`); `internal/adapters/outbox` — the watermill-sql publisher on the transaction and the forwarder; `internal/adapters/control` — the `GetDispatch` query.
- `internal/transport/grpc` — the listener with protovalidate and the error mapping; `internal/bootstrap` — Fx assembly, generations, the health/metrics listener.
- `deploy/chart` — the Helm chart (the service plus the owner queue relay sidecar from the background-worker image).

## Checks

`GOWORK=off GOFLAGS=-mod=readonly go build ./... && go vet ./... && go test ./...` (Docker-backed PostgreSQL 17 tests through Testcontainers; the migrations are found beside this repository in the parent checkout or through `ANVILKIT_MCP_MIGRATIONS_DIR`; `ANVILKIT_SKIP_DOCKER_TESTS=1` skips them), `sh tools/sqlc.sh --check`, `docker build .`, `helm lint deploy/chart`.

## Semantics the tests prove

Domain and outbox writes commit or roll back together; an earlier allocated but later committed outbox transaction is not skipped (the adapter's xid8 watermark); a restarted subscriber resumes from its offsets. Two racing claims produce one claimant; a worker identity claims a generation once; a superseded, expired or fenced claimant's heartbeat and result are refused; an identical repeated submission returns the existing acceptance; input-digest mismatches change nothing; profile mismatches and reported failures consume the attempt within the bound; a revoked authorization cancels instead of accepting; an expired external-effect lease is released only with Control's not-sent evidence, otherwise the request is dead with `EFFECT_UNCERTAIN`. Startup failure unwinds the listeners; secret rotation replaces the pool and drains the old one; a rejected candidate leaves the active generation.
