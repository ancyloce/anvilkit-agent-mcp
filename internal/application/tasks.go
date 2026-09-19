// Package application executes the owner's background-task commands (DD-09
// §1) inside one transaction each: the domain decision under the row lock
// of the generation, the attempt record, the CAS update and the outbox
// event through the same pgx.Tx. No network, queue or NATS I/O happens
// while a row is locked; the original-dispatch query of an external-effect
// lease runs before the transaction that consumes its answer.
package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// ErrForbidden: the request's authorization is not current.
var ErrForbidden = errors.New("FORBIDDEN")

// Clock is the owner's time source (tests inject one).
type Clock interface{ Now() time.Time }

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// DispatchQuery asks Control about the original dispatch of an
// external-effect attempt (DD-02 §4). The disabled implementation answers
// unknown, which never releases a lease.
type DispatchQuery interface {
	Outcome(ctx context.Context, dispatchID string) (domain.DispatchOutcome, error)
}

// NoDispatchQuery is the placement-less query: every answer is unknown.
type NoDispatchQuery struct{}

func (NoDispatchQuery) Outcome(context.Context, string) (domain.DispatchOutcome, error) {
	return domain.DispatchUnknown, nil
}

// Tasks is the BackgroundTaskService owner.
type Tasks struct {
	store     *postgres.Store
	dispatch  DispatchQuery
	bounds    atomic.Pointer[domain.Bounds]
	expiresAt atomic.Pointer[time.Time]
	clock     Clock
	log       *slog.Logger
	metrics   *Metrics
}

func NewTasks(store *postgres.Store, dispatch DispatchQuery, bounds domain.Bounds, clock Clock, log *slog.Logger, metrics *Metrics) *Tasks {
	t := &Tasks{store: store, dispatch: dispatch, clock: clock, log: log, metrics: metrics}
	t.bounds.Store(&bounds)
	return t
}

// Bounds are the bounds of the active configuration generation; a new
// generation replaces them whole (SetBounds) and governs new admissions
// only — requests froze their attempt bound and leases their length.
func (t *Tasks) Bounds() domain.Bounds { return *t.bounds.Load() }

func (t *Tasks) SetBounds(b domain.Bounds)  { t.bounds.Store(&b) }
func (t *Tasks) SetExpiry(expiry time.Time) { t.expiresAt.Store(&expiry) }
func (t *Tasks) Ready() bool {
	expiry := t.expiresAt.Load()
	return expiry == nil || expiry.IsZero() || t.clock.Now().Before(*expiry)
}
func (t *Tasks) admitConfiguration() error {
	if !t.Ready() {
		return fmt.Errorf("%w: active configuration expired", domain.ErrStaleExecution)
	}
	return nil
}

// RequestInput is a new durable request (an owner-internal command: the
// catalog lifecycle of P18 and the DEVELOPMENT_ONLY local-check entry
// point create them; there is no public create RPC).
type RequestInput struct {
	TaskID           string
	TenantID         string
	Kind             string
	Profile          string
	Input            []byte
	Effects          domain.Effects
	DispatchID       string
	AuthorizationRef string
	CorrelationID    string
}

// Request commits the durable request and its background.requested event
// in one transaction (DD-09 §1 "commits BackgroundRequest and outbox before
// queueing"). The same task with the same input returns the existing
// generation; a different input creates the next generation and fences the
// previous one (stale, with its own background.completed).
func (t *Tasks) Request(ctx context.Context, in RequestInput) (task domain.Task, existing bool, err error) {
	err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		if err := t.admitConfiguration(); err != nil {
			return err
		}
		if len(in.Input) > t.Bounds().MaxInputBytes {
			return fmt.Errorf("%w: %d bytes over the %d-byte bound", domain.ErrInputTooLarge, len(in.Input), t.Bounds().MaxInputBytes)
		}
		// The frozen input is the jsonb canonical text, so the bytes a claim
		// returns are exactly the bytes the digest binds.
		canonical, cErr := tx.Q.CanonicalJSON(ctx, in.Input)
		if cErr != nil {
			return fmt.Errorf("%w: input is not JSON", domain.ErrInvalid)
		}
		candidate, dErr := domain.NewRequest(in.TaskID, in.TenantID, in.Kind, in.Profile, []byte(canonical), in.Effects, in.DispatchID, in.AuthorizationRef, in.CorrelationID, t.Bounds())
		if dErr != nil {
			return dErr
		}
		now := t.clock.Now()
		latest, lErr := tx.Q.GetLatestRequestForUpdate(ctx, in.TaskID)
		switch {
		case lErr == nil:
			prev := postgres.TaskFromRow(latest)
			if prev.TenantID != in.TenantID {
				return fmt.Errorf("%w: task %s belongs to another tenant", ErrForbidden, in.TaskID)
			}
			if prev.InputDigest == candidate.InputDigest {
				task, existing = prev, true
				return nil
			}
			candidate.Generation = prev.Generation + 1
			if fenced, changed := domain.Supersede(prev); changed {
				if err := t.apply(ctx, tx, fenced, prev.Revision, now, attemptOutcomeIfLeased(prev, domain.AttemptStale)); err != nil {
					return err
				}
			}
		case errors.Is(lErr, pgx.ErrNoRows):
		default:
			return lErr
		}
		auth, aErr := postgres.GrantAuthorization(ctx, tx.Q, candidate.AuthorizationRef, candidate.TenantID, t.clock.Now)
		if aErr != nil {
			return aErr
		}
		if auth != domain.AuthorizationCurrent {
			return fmt.Errorf("%w: %s is not a current authorization", ErrForbidden, candidate.AuthorizationRef)
		}
		if err := t.admitConfiguration(); err != nil {
			return err
		}
		if err := tx.Q.InsertRequest(ctx, postgres.InsertParams(candidate)); err != nil {
			return err
		}
		ev, eErr := domain.RequestedEvent(candidate, now)
		if eErr != nil {
			return eErr
		}
		if err := outbox.Publish(ctx, tx.Tx, ev); err != nil {
			return err
		}
		task = candidate
		return nil
	})
	if err != nil {
		return domain.Task{}, false, err
	}
	t.log.Info("background request committed", "taskId", task.TaskID, "generation", task.Generation, "kind", task.Kind, "existing", existing)
	return task, existing, nil
}

func attemptOutcomeIfLeased(prev domain.Task, outcome string) string {
	if prev.State == domain.StateLeased {
		return outcome
	}
	return ""
}

// apply writes a decided row (CAS on the read revision), records the
// current attempt's outcome when one is given and publishes
// background.completed when the row became terminal.
func (t *Tasks) apply(ctx context.Context, tx postgres.Tx, task domain.Task, readRevision uint64, now time.Time, attemptOutcome string) error {
	n, err := tx.Q.UpdateRequest(ctx, postgres.UpdateParams(task, readRevision, now))
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: generation %d of %s changed under the lock", domain.ErrStaleExecution, task.Generation, task.TaskID)
	}
	if attemptOutcome != "" && task.AttemptCount > 0 {
		outcome := attemptOutcome
		if err := tx.Q.SetAttemptOutcome(ctx, sqlc.SetAttemptOutcomeParams{TaskID: task.TaskID, Generation: int64(task.Generation), Ordinal: int32(task.AttemptCount), Outcome: &outcome, SubmittedAt: pgtype.Timestamptz{Time: now, Valid: true}}); err != nil {
			return err
		}
	}
	if task.State.Terminal() {
		ev, err := domain.CompletedEvent(task, now)
		if err != nil {
			return err
		}
		if err := outbox.Publish(ctx, tx.Tx, ev); err != nil {
			return err
		}
	}
	return nil
}

func currentAttempt(task domain.Task, attempts []sqlc.TaskAttempt) domain.Attempt {
	for _, a := range attempts {
		if uint32(a.Ordinal) == task.AttemptCount {
			return postgres.AttemptFromRow(a)
		}
	}
	return domain.Attempt{}
}

// Claim admits one claimant for the generation (DD-09 §1): a conditional
// update under the row lock, one attempt per worker identity.
func (t *Tasks) Claim(ctx context.Context, taskID string, generation uint64, workerID string, lease time.Duration) (task domain.Task, input []byte, err error) {
	err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		if err := t.admitConfiguration(); err != nil {
			return err
		}
		row, err := tx.Q.GetRequestForUpdate(ctx, sqlc.GetRequestForUpdateParams{TaskID: taskID, Generation: int64(generation)})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s generation %d", domain.ErrNotFound, taskID, generation)
		}
		if err != nil {
			return err
		}
		attemptRows, err := tx.Q.ListAttempts(ctx, sqlc.ListAttemptsParams{TaskID: taskID, Generation: int64(generation)})
		if err != nil {
			return err
		}
		previous := make([]domain.Attempt, 0, len(attemptRows))
		for _, a := range attemptRows {
			previous = append(previous, postgres.AttemptFromRow(a))
		}
		current := postgres.TaskFromRow(row)
		if err := t.admitConfiguration(); err != nil {
			return err
		}
		now := t.clock.Now()
		d, err := domain.DecideClaim(current, previous, workerID, lease, now, t.Bounds())
		if err != nil {
			return err
		}
		if d.ExpiredPrevious {
			t.metrics.LeaseOverruns.Inc()
			expired := domain.AttemptExpired
			if err := tx.Q.SetAttemptOutcome(ctx, sqlc.SetAttemptOutcomeParams{TaskID: taskID, Generation: int64(generation), Ordinal: int32(current.AttemptCount), Outcome: &expired, SubmittedAt: pgtype.Timestamptz{Time: now, Valid: true}}); err != nil {
				return err
			}
		}
		if err := t.apply(ctx, tx, d.Task, current.Revision, now, ""); err != nil {
			return err
		}
		if err := tx.Q.InsertAttempt(ctx, sqlc.InsertAttemptParams{TaskID: taskID, Generation: int64(generation), Ordinal: int32(d.Attempt.Ordinal), WorkerID: workerID, LeasedAt: pgtype.Timestamptz{Time: now, Valid: true}, LeaseUntil: pgtype.Timestamptz{Time: d.Attempt.LeaseUntil, Valid: true}}); err != nil {
			return err
		}
		task, input = d.Task, current.Input
		return nil
	})
	switch {
	case err == nil:
		t.metrics.Claims.WithLabelValues("accepted").Inc()
	case errors.Is(err, domain.ErrAlreadyClaimed), errors.Is(err, postgres.ErrDuplicateKey):
		t.metrics.Claims.WithLabelValues("refused_claimed").Inc()
	case errors.Is(err, domain.ErrDuplicateClaimID):
		t.metrics.Claims.WithLabelValues("refused_identity").Inc()
	case errors.Is(err, domain.ErrEffectUncertain):
		t.metrics.Claims.WithLabelValues("refused_effect_uncertain").Inc()
	default:
		t.metrics.Claims.WithLabelValues("refused").Inc()
	}
	if err != nil {
		return domain.Task{}, nil, err
	}
	return task, input, nil
}

// Heartbeat extends the current claimant's valid lease.
func (t *Tasks) Heartbeat(ctx context.Context, taskID string, generation uint64, workerID string) (task domain.Task, err error) {
	err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		row, err := tx.Q.GetRequestForUpdate(ctx, sqlc.GetRequestForUpdateParams{TaskID: taskID, Generation: int64(generation)})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s generation %d", domain.ErrNotFound, taskID, generation)
		}
		if err != nil {
			return err
		}
		attempts, err := tx.Q.ListAttempts(ctx, sqlc.ListAttemptsParams{TaskID: taskID, Generation: int64(generation)})
		if err != nil {
			return err
		}
		current := postgres.TaskFromRow(row)
		extended, err := domain.DecideHeartbeat(current, currentAttempt(current, attempts), workerID, t.clock.Now())
		if err != nil {
			return err
		}
		if err := t.apply(ctx, tx, extended, current.Revision, t.clock.Now(), ""); err != nil {
			return err
		}
		task = extended
		return nil
	})
	return task, err
}

// Submit accepts or refuses a result under the owner's CAS; acceptance and
// background.completed commit together.
func (t *Tasks) Submit(ctx context.Context, taskID string, generation uint64, sub domain.Submission) (decision domain.SubmitDecision, err error) {
	err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		row, err := tx.Q.GetRequestForUpdate(ctx, sqlc.GetRequestForUpdateParams{TaskID: taskID, Generation: int64(generation)})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s generation %d", domain.ErrNotFound, taskID, generation)
		}
		if err != nil {
			return err
		}
		attempts, err := tx.Q.ListAttempts(ctx, sqlc.ListAttemptsParams{TaskID: taskID, Generation: int64(generation)})
		if err != nil {
			return err
		}
		current := postgres.TaskFromRow(row)
		auth, err := postgres.GrantAuthorization(ctx, tx.Q, current.AuthorizationRef, current.TenantID, t.clock.Now)
		if err != nil {
			return err
		}
		now := t.clock.Now()
		d, err := domain.DecideSubmit(current, currentAttempt(current, attempts), sub, auth, now, t.Bounds())
		if err != nil {
			return err
		}
		if d.Changed {
			if err := t.apply(ctx, tx, d.Task, current.Revision, now, d.AttemptOutcome); err != nil {
				return err
			}
		}
		decision = d
		return nil
	})
	switch {
	case err != nil && errors.Is(err, domain.ErrStaleExecution):
		t.metrics.Submissions.WithLabelValues("refused_stale").Inc()
	case err != nil && errors.Is(err, domain.ErrInvalid):
		t.metrics.Submissions.WithLabelValues("refused_invalid").Inc()
	case err != nil:
		t.metrics.Submissions.WithLabelValues("refused").Inc()
	case decision.Existing:
		t.metrics.Submissions.WithLabelValues("existing").Inc()
	case decision.Accepted:
		t.metrics.Submissions.WithLabelValues("accepted").Inc()
	case decision.Task.State == domain.StateCanceled:
		t.metrics.Submissions.WithLabelValues("revoked").Inc()
	case decision.Task.FailureCode == domain.FailureProfileMismatch:
		t.metrics.Submissions.WithLabelValues("profile_mismatch").Inc()
	default:
		t.metrics.Submissions.WithLabelValues("failed").Inc()
	}
	return decision, err
}

// Get returns the latest generation of a task without its input.
func (t *Tasks) Get(ctx context.Context, taskID string) (domain.Task, error) {
	row, err := t.store.Queries().GetLatestRequest(ctx, taskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Task{}, fmt.Errorf("%w: %s", domain.ErrNotFound, taskID)
	}
	if err != nil {
		return domain.Task{}, err
	}
	task := postgres.TaskFromRow(row)
	task.Input = nil
	return task, nil
}

// Cancel cancels the latest generation (owner-internal command).
func (t *Tasks) Cancel(ctx context.Context, taskID string) (task domain.Task, changed bool, err error) {
	err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		row, err := tx.Q.GetLatestRequestForUpdate(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", domain.ErrNotFound, taskID)
		}
		if err != nil {
			return err
		}
		current := postgres.TaskFromRow(row)
		canceled, outcome, did := domain.DecideCancel(current)
		if did {
			if err := t.apply(ctx, tx, canceled, current.Revision, t.clock.Now(), outcome); err != nil {
				return err
			}
		}
		task, changed = canceled, did
		return nil
	})
	return task, changed, err
}

// SweepExpired settles leases that ran out (DD-09 §1). External-effect
// leases are queried at Control before the transaction; the answer is
// consumed under the lock and nothing is resent on an unknown outcome.
func (t *Tasks) SweepExpired(ctx context.Context, limit int32) (int, error) {
	now := t.clock.Now()
	expired, err := t.store.Queries().ListExpiredLeases(ctx, sqlc.ListExpiredLeasesParams{LeaseUntil: pgtype.Timestamptz{Time: now, Valid: true}, Limit: limit})
	if err != nil {
		return 0, err
	}
	settled := 0
	for _, e := range expired {
		row, err := t.store.Queries().GetRequest(ctx, sqlc.GetRequestParams{TaskID: e.TaskID, Generation: e.Generation})
		if err != nil {
			continue
		}
		task := postgres.TaskFromRow(row)
		outcome := domain.DispatchUnknown
		if task.Effects == domain.EffectsExternal {
			answer, qErr := t.dispatch.Outcome(ctx, task.DispatchID)
			if qErr != nil {
				t.metrics.DispatchQueries.WithLabelValues("error").Inc()
				t.log.Warn("original dispatch query failed; the lease stays unreleased", "taskId", task.TaskID, "generation", task.Generation, "error", qErr)
				continue
			}
			outcome = answer
			t.metrics.DispatchQueries.WithLabelValues(map[domain.DispatchOutcome]string{domain.DispatchNotSent: "not_sent", domain.DispatchSent: "sent", domain.DispatchUnknown: "unknown"}[answer]).Inc()
		}
		err = t.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
			locked, err := tx.Q.GetRequestForUpdate(ctx, sqlc.GetRequestForUpdateParams{TaskID: e.TaskID, Generation: e.Generation})
			if err != nil {
				return err
			}
			current := postgres.TaskFromRow(locked)
			decided, attemptOutcome, changed := domain.DecideExpire(current, outcome, t.clock.Now(), t.Bounds())
			if !changed {
				return nil
			}
			settled++
			t.metrics.LeaseOverruns.Inc()
			return t.apply(ctx, tx, decided, current.Revision, t.clock.Now(), attemptOutcome)
		})
		if err != nil {
			t.log.Warn("lease expiry not settled", "taskId", e.TaskID, "generation", e.Generation, "error", err)
		}
	}
	return settled, nil
}

// Observe refreshes the gauges the sweeper owns (request counts, overdue
// retries, the oldest unforwarded outbox message).
func (t *Tasks) Observe(ctx context.Context, consumerGroup string) {
	q := t.store.Queries()
	if counts, err := q.CountRequestsByState(ctx); err == nil {
		for _, s := range []domain.TaskState{domain.StatePending, domain.StateLeased, domain.StateResultSubmitted, domain.StateAccepted, domain.StateRetryScheduled, domain.StateDead, domain.StateStale, domain.StateCanceled} {
			t.metrics.Requests.WithLabelValues(string(s)).Set(0)
		}
		for _, c := range counts {
			t.metrics.Requests.WithLabelValues(c.State).Set(float64(c.N))
		}
	}
	if n, err := q.CountOverdueRetries(ctx, pgtype.Timestamptz{Time: t.clock.Now(), Valid: true}); err == nil {
		t.metrics.OverdueRetries.Set(float64(n))
	}
	if age, err := q.OldestUnforwardedSeconds(ctx, consumerGroup); err == nil {
		t.metrics.OutboxOldest.Set(age)
	}
	stat := t.store.Pool().Stat()
	t.metrics.PoolAcquired.Set(float64(stat.AcquiredConns()))
	t.metrics.PoolTotal.Set(float64(stat.TotalConns()))
}
