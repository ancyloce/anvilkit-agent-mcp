package application_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	wmsql "github.com/ThreeDotsLabs/watermill-sql/v4/pkg/sql"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/testdb"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeDispatch struct {
	outcome domain.DispatchOutcome
	calls   int
}

func (f *fakeDispatch) Outcome(context.Context, string) (domain.DispatchOutcome, error) {
	f.calls++
	return f.outcome, nil
}

var bounds = domain.Bounds{MaxInputBytes: 65536, MaxLease: time.Hour, RetryDelay: 5 * time.Second, MaxAttempts: 2}

type harness struct {
	inst     *testdb.Instance
	store    *postgres.Store
	tasks    *application.Tasks
	clock    *fakeClock
	dispatch *fakeDispatch
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	inst := testdb.Start(t)
	pool := inst.Pool(t)
	store := postgres.NewStore(pool)
	clock := &fakeClock{now: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)}
	dispatch := &fakeDispatch{outcome: domain.DispatchUnknown}
	tasks := application.NewTasks(store, dispatch, bounds, clock, slog.New(slog.NewTextHandler(io.Discard, nil)), application.NewMetrics(prometheus.NewRegistry()))
	inst.GrantFixture(t, "tenant_a", "g1", "active")
	return &harness{inst: inst, store: store, tasks: tasks, clock: clock, dispatch: dispatch}
}

func localCheckInput(t *testing.T, payload string) []byte {
	t.Helper()
	raw, err := json.Marshal(domain.LocalCheckInput{SchemaVersion: 1, Computation: domain.LocalCheckProfile, Bytes: base64.StdEncoding.EncodeToString([]byte(payload))})
	require.NoError(t, err)
	return raw
}

func (h *harness) request(t *testing.T, taskID, payload string) domain.Task {
	t.Helper()
	task, _, err := h.tasks.Request(context.Background(), application.RequestInput{
		TaskID: taskID, TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, payload),
		Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:g1", CorrelationID: "req_" + taskID,
	})
	require.NoError(t, err)
	return task
}

// outboxRows reads the physical outbox rows (as the app role) in commit order.
func (h *harness) outboxRows(t *testing.T) []map[string]any {
	t.Helper()
	rows, err := h.store.Pool().Query(context.Background(), `SELECT payload::text FROM outbox ORDER BY transaction_id, "offset"`)
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var payload string
		require.NoError(t, rows.Scan(&payload))
		var env map[string]any
		require.NoError(t, json.Unmarshal([]byte(payload), &env))
		out = append(out, env)
	}
	return out
}

func decodeEnvelope(t *testing.T, row map[string]any) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(row["payload"].(string))
	require.NoError(t, err)
	var env map[string]any
	require.NoError(t, json.Unmarshal(raw, &env))
	return env
}

func TestRequestCommitsWithOutboxOrNotAtAll(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	task := h.request(t, "task_1", "hello")
	require.Equal(t, uint64(1), task.Generation)
	require.Equal(t, domain.InputDigest(task.Input), task.InputDigest, "the digest binds the canonical bytes a claim returns")

	rows := h.outboxRows(t)
	require.Len(t, rows, 1)
	require.Equal(t, domain.SubjectBackgroundRequested, rows[0]["destination_topic"])
	env := decodeEnvelope(t, rows[0])
	require.Equal(t, "background.requested", env["eventType"])
	require.Equal(t, "tenant_a", env["tenantId"])
	require.Equal(t, "1", env["aggregateRevision"])
	require.Equal(t, "local-check", env["payload"].(map[string]any)["taskKind"])

	// Same task, same input: the existing generation, no second event.
	again, existing, err := h.tasks.Request(ctx, application.RequestInput{TaskID: "task_1", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "hello"), Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:g1", CorrelationID: "req_x"})
	require.NoError(t, err)
	require.True(t, existing)
	require.Equal(t, task.Generation, again.Generation)
	require.Len(t, h.outboxRows(t), 1)

	// Rollback: a request refused inside the transaction leaves neither a row nor an outbox message.
	_, _, err = h.tasks.Request(ctx, application.RequestInput{TaskID: "task_2", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: "parser-v1", Input: localCheckInput(t, "x"), Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:g1", CorrelationID: "req_2"})
	require.ErrorIs(t, err, domain.ErrProfileUnknown)
	_, err = h.tasks.Get(ctx, "task_2")
	require.ErrorIs(t, err, domain.ErrNotFound)
	require.Len(t, h.outboxRows(t), 1)

	// A request under a revoked or missing authorization is refused.
	_, _, err = h.tasks.Request(ctx, application.RequestInput{TaskID: "task_3", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "x"), Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:missing", CorrelationID: "req_3"})
	require.ErrorIs(t, err, application.ErrForbidden)

	// New input supersedes: the old generation is stale with its completed event, the new one pending.
	next := h.request(t, "task_1", "hello-2")
	require.Equal(t, uint64(2), next.Generation)
	old, err := h.store.Queries().GetRequest(ctx, struct {
		TaskID     string
		Generation int64
	}{"task_1", 1})
	require.NoError(t, err)
	require.Equal(t, "stale", old.State)
	rows = h.outboxRows(t)
	require.Len(t, rows, 3)
	require.Equal(t, domain.SubjectBackgroundCompleted, rows[1]["destination_topic"])
	require.Equal(t, "stale", decodeEnvelope(t, rows[1])["payload"].(map[string]any)["state"])
}

func TestClaimRaceAndFences(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	task := h.request(t, "task_r", "race")

	// Two instances racing one claim: exactly one currently valid claimant.
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, results[i] = h.tasks.Claim(ctx, task.TaskID, task.Generation, fmt.Sprintf("w%d", i), time.Minute)
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else {
			require.True(t, errors.Is(err, domain.ErrAlreadyClaimed) || errors.Is(err, postgres.ErrDuplicateKey), "loser: %v", err)
		}
	}
	require.Equal(t, 1, winners)
	got, err := h.tasks.Get(ctx, task.TaskID)
	require.NoError(t, err)
	require.Equal(t, domain.StateLeased, got.State)
	winner := got.WorkerID

	// The claimant heartbeats; a stranger cannot.
	_, err = h.tasks.Heartbeat(ctx, task.TaskID, task.Generation, winner)
	require.NoError(t, err)
	_, err = h.tasks.Heartbeat(ctx, task.TaskID, task.Generation, "stranger")
	require.ErrorIs(t, err, domain.ErrStaleExecution)

	// Lease expiry: the sweeper reschedules; the old claimant is fenced even
	// when its identifier tries again (one claim per identity per generation).
	h.clock.Advance(2 * time.Minute)
	n, err := h.tasks.SweepExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	got, _ = h.tasks.Get(ctx, task.TaskID)
	require.Equal(t, domain.StateRetryScheduled, got.State)
	require.Equal(t, domain.FailureLeaseExpired, got.FailureCode)
	_, _, err = h.tasks.Claim(ctx, task.TaskID, task.Generation, "w8", time.Minute)
	require.ErrorIs(t, err, domain.ErrNotClaimable, "retry not due yet")
	h.clock.Advance(bounds.RetryDelay)
	_, _, err = h.tasks.Claim(ctx, task.TaskID, task.Generation, winner, time.Minute)
	require.ErrorIs(t, err, domain.ErrDuplicateClaimID)
	_, input, err := h.tasks.Claim(ctx, task.TaskID, task.Generation, "w9", time.Minute)
	require.NoError(t, err)
	require.Equal(t, task.InputDigest, domain.InputDigest(input))
	ref, digest, err := domain.ExpectedResult(task)
	require.NoError(t, err)
	// The superseded claimant's result cannot overwrite the current attempt.
	_, err = h.tasks.Submit(ctx, task.TaskID, task.Generation, domain.Submission{WorkerID: winner, InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest})
	require.ErrorIs(t, err, domain.ErrStaleExecution)
	// The current claimant's result is accepted, together with background.completed.
	d, err := h.tasks.Submit(ctx, task.TaskID, task.Generation, domain.Submission{WorkerID: "w9", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest})
	require.NoError(t, err)
	require.True(t, d.Accepted)
	rows := h.outboxRows(t)
	last := decodeEnvelope(t, rows[len(rows)-1])
	require.Equal(t, "background.completed", last["eventType"])
	require.Equal(t, digest, last["payload"].(map[string]any)["resultDigest"])
	// An old generation cannot be claimed once superseded.
	h.request(t, "task_r", "race-2")
	_, _, err = h.tasks.Claim(ctx, task.TaskID, 1, "w10", time.Minute)
	require.ErrorIs(t, err, domain.ErrNotClaimable)
}

func TestSubmitRulesOnRealRows(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	task := h.request(t, "task_s", "submit")
	_, _, err := h.tasks.Claim(ctx, task.TaskID, 1, "w1", time.Minute)
	require.NoError(t, err)
	ref, digest, _ := domain.ExpectedResult(task)
	wrong := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	_, err = h.tasks.Submit(ctx, task.TaskID, 1, domain.Submission{WorkerID: "w1", InputDigest: wrong, Succeeded: true, ResultRef: ref, ResultDigest: digest})
	require.ErrorIs(t, err, domain.ErrInvalid, "input digest mismatch is refused without a state change")
	got, _ := h.tasks.Get(ctx, task.TaskID)
	require.Equal(t, domain.StateLeased, got.State)

	d, err := h.tasks.Submit(ctx, task.TaskID, 1, domain.Submission{WorkerID: "w1", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: wrong})
	require.NoError(t, err)
	require.False(t, d.Accepted)
	require.Equal(t, domain.StateRetryScheduled, d.Task.State)
	require.Equal(t, domain.FailureProfileMismatch, d.Task.FailureCode)

	// Revocation between claim and submission cancels instead of accepting.
	h.clock.Advance(bounds.RetryDelay)
	_, _, err = h.tasks.Claim(ctx, task.TaskID, 1, "w2", time.Minute)
	require.NoError(t, err)
	h.inst.SetGrantState(t, "g1", "revoked")
	d, err = h.tasks.Submit(ctx, task.TaskID, 1, domain.Submission{WorkerID: "w2", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest})
	require.NoError(t, err)
	require.False(t, d.Accepted)
	require.Equal(t, domain.StateCanceled, d.Task.State)
	require.Equal(t, domain.FailureAuthorizationRevoked, d.Task.FailureCode)
	rows := h.outboxRows(t)
	require.Equal(t, "canceled", decodeEnvelope(t, rows[len(rows)-1])["payload"].(map[string]any)["state"])
	h.inst.SetGrantState(t, "g1", "active")

	// Acceptance, then the identical repeat is existing; cancel afterwards is a no-op.
	task2 := h.request(t, "task_s2", "submit-2")
	_, _, err = h.tasks.Claim(ctx, task2.TaskID, 1, "w1", time.Minute)
	require.NoError(t, err)
	ref2, digest2, _ := domain.ExpectedResult(task2)
	sub := domain.Submission{WorkerID: "w1", InputDigest: task2.InputDigest, Succeeded: true, ResultRef: ref2, ResultDigest: digest2}
	d, err = h.tasks.Submit(ctx, task2.TaskID, 1, sub)
	require.NoError(t, err)
	require.True(t, d.Accepted && !d.Existing)
	d, err = h.tasks.Submit(ctx, task2.TaskID, 1, sub)
	require.NoError(t, err)
	require.True(t, d.Accepted && d.Existing)
	_, changed, err := h.tasks.Cancel(ctx, task2.TaskID)
	require.NoError(t, err)
	require.False(t, changed)
	before := len(h.outboxRows(t))

	// A reported failure on the last attempt is dead; the attempts table holds the history.
	task3 := h.request(t, "task_s3", "submit-3")
	for i, code := range []string{"HANDLER_FAILED", "HANDLER_FAILED"} {
		_, _, err = h.tasks.Claim(ctx, task3.TaskID, 1, fmt.Sprintf("w%d", i), time.Minute)
		require.NoError(t, err)
		d, err = h.tasks.Submit(ctx, task3.TaskID, 1, domain.Submission{WorkerID: fmt.Sprintf("w%d", i), InputDigest: task3.InputDigest, Succeeded: false, FailureCode: code})
		require.NoError(t, err)
		h.clock.Advance(bounds.RetryDelay)
	}
	require.Equal(t, domain.StateDead, d.Task.State)
	attempts, err := h.store.Queries().ListAttempts(ctx, struct {
		TaskID     string
		Generation int64
	}{task3.TaskID, 1})
	require.NoError(t, err)
	require.Len(t, attempts, 2)
	require.Equal(t, "failed", *attempts[1].Outcome)
	require.Len(t, h.outboxRows(t), before+2, "requested and completed(dead)")
}

func TestExternalEffectLeaseNeverBlindlyReassigned(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	task, _, err := h.tasks.Request(ctx, application.RequestInput{
		TaskID: "task_x", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "ext"),
		Effects: domain.EffectsExternal, DispatchID: "disp_1", AuthorizationRef: "grant:g1", CorrelationID: "req_x",
	})
	require.NoError(t, err)
	_, _, err = h.tasks.Claim(ctx, task.TaskID, 1, "w1", time.Minute)
	require.NoError(t, err)
	h.clock.Advance(2 * time.Minute)
	// A claim on the expired external lease is refused; the sweeper asks Control.
	_, _, err = h.tasks.Claim(ctx, task.TaskID, 1, "w2", time.Minute)
	require.ErrorIs(t, err, domain.ErrEffectUncertain)
	h.dispatch.outcome = domain.DispatchUnknown
	_, err = h.tasks.SweepExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, h.dispatch.calls)
	got, _ := h.tasks.Get(ctx, task.TaskID)
	require.Equal(t, domain.StateDead, got.State)
	require.Equal(t, domain.FailureEffectUncertain, got.FailureCode)

	// With not-sent evidence the lease is released for one more attempt.
	task2, _, err := h.tasks.Request(ctx, application.RequestInput{
		TaskID: "task_y", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "ext2"),
		Effects: domain.EffectsExternal, DispatchID: "disp_2", AuthorizationRef: "grant:g1", CorrelationID: "req_y",
	})
	require.NoError(t, err)
	_, _, err = h.tasks.Claim(ctx, task2.TaskID, 1, "w1", time.Minute)
	require.NoError(t, err)
	h.clock.Advance(2 * time.Minute)
	h.dispatch.outcome = domain.DispatchNotSent
	_, err = h.tasks.SweepExpired(ctx, 10)
	require.NoError(t, err)
	got, _ = h.tasks.Get(ctx, task2.TaskID)
	require.Equal(t, domain.StateRetryScheduled, got.State)
}

// TestOutboxAdapterVisibility proves, with the pinned watermill-sql
// subscriber over the migration's physical schema, that an earlier
// allocated but later committed transaction is not skipped (the xid8
// watermark, not a maximum BIGSERIAL cursor), that a rolled-back insert
// never appears and that a restarted subscriber resumes from its offsets.
func TestOutboxAdapterVisibility(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.store.Pool()
	publish := func(tx pgx.Tx, id string) {
		env := domain.Envelope{EventID: id, EventType: "background.requested", SchemaVersion: 1, Producer: domain.Producer, Subject: domain.SubjectBackgroundRequested, TenantID: "tenant_a", AggregateType: domain.AggregateBackgroundRequest, AggregateID: "task", AggregateRevision: "1", OccurredAt: "2026-09-17T12:00:00Z", CorrelationID: "c", Payload: json.RawMessage(`{"kind":"background.requested","taskId":"task","generation":"1","taskKind":"local-check","inputDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`)}
		require.NoError(t, outbox.Publish(ctx, tx, env))
	}
	newSubscriber := func() *wmsql.Subscriber {
		ack := 5 * time.Second
		sub, err := wmsql.NewSubscriber(wmsql.BeginnerFromPgx(pool), wmsql.SubscriberConfig{ConsumerGroup: "test-forwarder", AckDeadline: &ack, PollInterval: 50 * time.Millisecond, ResendInterval: 50 * time.Millisecond, RetryInterval: 50 * time.Millisecond, SchemaAdapter: outbox.Schema(10), OffsetsAdapter: outbox.Offsets()}, watermill.NopLogger{})
		require.NoError(t, err)
		return sub
	}
	receive := func(ch <-chan *message.Message, wait time.Duration) (*message.Message, bool) {
		select {
		case m := <-ch:
			return m, true
		case <-time.After(wait):
			return nil, false
		}
	}
	unwrapID := func(m *message.Message) string {
		var env map[string]any
		require.NoError(t, json.Unmarshal(m.Payload, &env))
		return env["uuid"].(string)
	}

	// A: allocates its offset first, commits last. B: allocates second, commits first.
	txA, err := pool.Begin(ctx)
	require.NoError(t, err)
	publish(txA, "aaaaaaaa-0000-4000-8000-000000000001")
	txB, err := pool.Begin(ctx)
	require.NoError(t, err)
	publish(txB, "bbbbbbbb-0000-4000-8000-000000000002")
	require.NoError(t, txB.Commit(ctx))
	// A rolled-back insert: never delivered.
	txR, err := pool.Begin(ctx)
	require.NoError(t, err)
	publish(txR, "cccccccc-0000-4000-8000-000000000003")
	require.NoError(t, txR.Rollback(ctx))

	sub := newSubscriber()
	subCtx, cancelSub := context.WithCancel(ctx)
	ch, err := sub.Subscribe(subCtx, outbox.ForwarderTopic)
	require.NoError(t, err)
	_, got := receive(ch, 700*time.Millisecond)
	require.False(t, got, "B must stay invisible while the earlier transaction A is in progress")
	require.NoError(t, txA.Commit(ctx))
	first, got := receive(ch, 5*time.Second)
	require.True(t, got)
	require.Equal(t, "aaaaaaaa-0000-4000-8000-000000000001", unwrapID(first))
	first.Ack()
	second, got := receive(ch, 5*time.Second)
	require.True(t, got)
	require.Equal(t, "bbbbbbbb-0000-4000-8000-000000000002", unwrapID(second))
	// Not acked before the subscriber closes: the batch's acks up to A commit
	// (Close lets the adapter's ack query run; a canceled context would roll
	// the whole batch back and redeliver A too — at-least-once either way,
	// which Nats-Msg-Id and the consumers' inboxes absorb) and a restarted
	// subscriber resumes from its offsets with B and nothing else.
	require.NoError(t, sub.Close())
	cancelSub()

	sub2 := newSubscriber()
	subCtx2, cancelSub2 := context.WithCancel(ctx)
	defer cancelSub2()
	ch2, err := sub2.Subscribe(subCtx2, outbox.ForwarderTopic)
	require.NoError(t, err)
	again, got := receive(ch2, 5*time.Second)
	require.True(t, got)
	require.Equal(t, "bbbbbbbb-0000-4000-8000-000000000002", unwrapID(again))
	again.Ack()
	_, got = receive(ch2, 500*time.Millisecond)
	require.False(t, got, "the rolled-back message never appears")
	cancelSub2()
	require.NoError(t, sub2.Close())

	var acked int64
	require.NoError(t, pool.QueryRow(ctx, "SELECT offset_acked FROM outbox_offsets WHERE consumer_group = 'test-forwarder'").Scan(&acked))
	require.Equal(t, int64(2), acked)
}

func TestGrantTenantAndExpiryAtCreationAndAcceptance(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, scenario := range []string{"foreign", "expired", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			h.inst.Admin(t, "UPDATE grants SET tenant_id='tenant_a', state='active', expires_at='2027-01-01' WHERE grant_id='g1'")
			alter := func() {
				switch scenario {
				case "foreign":
					h.inst.Admin(t, "UPDATE grants SET tenant_id='tenant_b' WHERE grant_id='g1'")
				case "expired":
					h.inst.Admin(t, "UPDATE grants SET expires_at='2026-09-17 12:00:00+00' WHERE grant_id='g1'")
				}
			}
			alter()
			_, _, err := h.tasks.Request(ctx, application.RequestInput{TaskID: "create_" + scenario, TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "hello"), Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:g1", CorrelationID: "req_test"})
			if scenario == "valid" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, application.ErrForbidden)
			}
			h.inst.Admin(t, "UPDATE grants SET tenant_id='tenant_a', expires_at='2027-01-01' WHERE grant_id='g1'")
			task := h.request(t, "accept_"+scenario, "hello")
			_, _, err = h.tasks.Claim(ctx, task.TaskID, 1, "worker", time.Minute)
			require.NoError(t, err)
			alter()
			ref, digest, err := domain.ExpectedResult(task)
			require.NoError(t, err)
			result, err := h.tasks.Submit(ctx, task.TaskID, 1, domain.Submission{WorkerID: "worker", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest})
			require.NoError(t, err)
			require.Equal(t, scenario == "valid", result.Accepted)
		})
	}
}

func TestExpiredConfigurationPreservesInflightBounds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.tasks.SetExpiry(h.clock.Now().Add(time.Second))
	task := h.request(t, "frozen_expiry", "frozen")
	_, _, err := h.tasks.Claim(ctx, task.TaskID, 1, "frozen-worker", time.Minute)
	require.NoError(t, err)
	changed := bounds
	changed.MaxAttempts = 1
	changed.MaxLease = time.Second
	h.tasks.SetBounds(changed)
	h.clock.Advance(2 * time.Second)
	require.False(t, h.tasks.Ready())
	_, _, err = h.tasks.Request(ctx, application.RequestInput{TaskID: "new_expired", TenantID: "tenant_a", Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: localCheckInput(t, "new"), Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:g1", CorrelationID: "req_new"})
	require.ErrorIs(t, err, domain.ErrStaleExecution)
	beat, err := h.tasks.Heartbeat(ctx, task.TaskID, 1, "frozen-worker")
	require.NoError(t, err)
	require.Equal(t, bounds.MaxAttempts, beat.MaxAttempts)
	ref, digest, err := domain.ExpectedResult(task)
	require.NoError(t, err)
	done, err := h.tasks.Submit(ctx, task.TaskID, 1, domain.Submission{WorkerID: "frozen-worker", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest})
	require.NoError(t, err)
	require.True(t, done.Accepted)
}
