// Package postgres is the MCP owner's data access (A05/A06): one pgx
// transaction per owner command, the sqlc queries over it and, through the
// outbox publisher, the watermill-sql insert of the same transaction. The
// runtime role has DML only; no statement here creates or alters schema.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// ErrDuplicateKey is a unique-violation from a concurrent identical write.
var ErrDuplicateKey = errors.New("duplicate key")

// Store runs owner transactions on the app-role pool of the active
// configuration generation. A rotated secret publishes a new pool through
// Swap; transactions already running keep the connection they acquired
// from the previous pool, which the generation watcher drains afterwards.
type Store struct {
	current atomic.Pointer[pgxpool.Pool]
}

func NewStore(pool *pgxpool.Pool) *Store {
	s := &Store{}
	s.current.Store(pool)
	return s
}

// Pool is the active generation's pool (the forwarder subscriber and the
// metrics reader take it at construction of their generation).
func (s *Store) Pool() *pgxpool.Pool { return s.current.Load() }

// Swap publishes the pool of a new generation and returns the previous one
// for draining.
func (s *Store) Swap(next *pgxpool.Pool) (previous *pgxpool.Pool) { return s.current.Swap(next) }

// Tx is one owner transaction: the pgx transaction (for the outbox
// publisher) and the queries over it.
type Tx struct {
	pgx.Tx
	Q *sqlc.Queries
}

// InTx runs fn in one read-committed transaction; a unique violation is
// reported as ErrDuplicateKey so callers can answer the idempotent case.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	tx, err := s.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(ctx, Tx{Tx: tx, Q: sqlc.New(tx)}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: %s", ErrDuplicateKey, pgErr.ConstraintName)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Queries returns read-only queries on the pool (no transaction).
func (s *Store) Queries() *sqlc.Queries { return sqlc.New(s.Pool()) }

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ts(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

func optTs(t *time.Time) pgtype.Timestamptz {
	if t == nil || t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// TaskFromRow maps the sqlc row to the domain request.
func TaskFromRow(r sqlc.BackgroundRequest) domain.Task {
	t := domain.Task{
		TaskID: r.TaskID, Generation: uint64(r.Generation), TenantID: r.TenantID, Kind: r.TaskKind, InputDigest: r.InputDigest, Input: r.Input,
		State: domain.TaskState(r.State), WorkerID: str(r.WorkerID), LeaseUntil: ts(r.LeaseUntil), AttemptCount: uint32(r.AttemptCount),
		MaxAttempts: uint32(r.MaxAttempts), ResultProfile: r.ResultProfile, Effects: domain.Effects(r.Effects), DispatchID: str(r.DispatchID),
		AuthorizationRef: r.AuthorizationRef, ResultRef: str(r.ResultRef), ResultDigest: str(r.ResultDigest), FailureCode: str(r.FailureCode),
		Revision: uint64(r.Revision), CorrelationID: r.CorrelationID,
	}
	if r.RetryAt.Valid {
		at := r.RetryAt.Time
		t.RetryAt = &at
	}
	return t
}

// AttemptFromRow maps the sqlc attempt row.
func AttemptFromRow(r sqlc.TaskAttempt) domain.Attempt {
	return domain.Attempt{Ordinal: uint32(r.Ordinal), WorkerID: r.WorkerID, LeasedAt: ts(r.LeasedAt), LeaseUntil: ts(r.LeaseUntil), Outcome: str(r.Outcome)}
}

// UpdateParams renders the domain row for the CAS update, which binds the
// revision the transaction read (the row lock already serializes writers;
// the revision guard is the belt to that suspender).
func UpdateParams(t domain.Task, readRevision uint64, now time.Time) sqlc.UpdateRequestParams {
	var lease pgtype.Timestamptz
	if !t.LeaseUntil.IsZero() && t.State == domain.StateLeased {
		lease = pgtype.Timestamptz{Time: t.LeaseUntil, Valid: true}
	}
	var completed pgtype.Timestamptz
	if t.State.Terminal() {
		completed = pgtype.Timestamptz{Time: now, Valid: true}
	}
	return sqlc.UpdateRequestParams{
		TaskID: t.TaskID, Generation: int64(t.Generation), State: string(t.State), WorkerID: optStr(t.WorkerID), LeaseUntil: lease,
		AttemptCount: int32(t.AttemptCount), RetryAt: optTs(t.RetryAt), ResultRef: optStr(t.ResultRef), ResultDigest: optStr(t.ResultDigest),
		FailureCode: optStr(t.FailureCode), Revision: int64(t.Revision), CompletedAt: completed, ExpectedRevision: int64(readRevision),
	}
}

// InsertParams renders a new generation.
func InsertParams(t domain.Task) sqlc.InsertRequestParams {
	return sqlc.InsertRequestParams{
		TaskID: t.TaskID, Generation: int64(t.Generation), TenantID: t.TenantID, TaskKind: t.Kind, InputDigest: t.InputDigest, Input: t.Input,
		State: string(t.State), MaxAttempts: int32(t.MaxAttempts), ResultProfile: t.ResultProfile, Effects: string(t.Effects), DispatchID: optStr(t.DispatchID),
		AuthorizationRef: t.AuthorizationRef, CorrelationID: t.CorrelationID,
	}
}

// GrantAuthorization answers the owner's current authorization for a
// grant:<grant_id> reference from the grants table of this transaction: an
// active grant is current; a revoked, revoking, expired, pending, failed or
// missing one is not (DD-08; the P18 grant lifecycle writes the rows).
func GrantAuthorization(ctx context.Context, q *sqlc.Queries, ref, tenantID string, now func() time.Time) (domain.AuthorizationState, error) {
	const prefix = "grant:"
	if len(ref) <= len(prefix) || ref[:len(prefix)] != prefix {
		return domain.AuthorizationRevoked, fmt.Errorf("%w: authorization reference %q", domain.ErrInvalid, ref)
	}
	grant, err := q.GetGrantState(ctx, ref[len(prefix):])
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuthorizationRevoked, nil
	}
	if err != nil {
		return domain.AuthorizationRevoked, err
	}
	if grant.TenantID == tenantID && grant.State == "active" && grant.ExpiresAt.Valid && now().Before(grant.ExpiresAt.Time) {
		return domain.AuthorizationCurrent, nil
	}
	return domain.AuthorizationRevoked, nil
}
