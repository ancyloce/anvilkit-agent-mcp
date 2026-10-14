package application_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// TestCatalogRefresh (P2.5 AC5 at the owner): a scheduled
// mcp-catalog-refresh request is created per callable approved revision,
// claimed, advanced by MCP's own live read and accepted only with the
// recorded result; an accepted drift disables the revision and begins the
// revocation of its grants in the acceptance transaction, so a call is
// refused as not executable rather than meeting the drift.
func TestCatalogRefresh(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()
	d := h.approved(t)
	g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
	require.NoError(t, err)
	require.Equal(t, domain.GrantActive, g.State)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tasks := application.NewTasks(h.store, application.NoDispatchQuery{}, domain.Bounds{MaxInputBytes: 65536, MaxLease: 10 * time.Minute, MaxAttempts: 3},
		h.clock, log, application.NewMetrics(prometheus.NewRegistry()))
	refresh := application.NewRefresh(h.store, h.catalog, tasks, h.clock, log)
	period := time.Hour
	taskOf := func() string {
		return fmt.Sprintf("refresh-%s-r%d-%d", d.ServerID, d.Revision, h.clock.Now().Unix()/int64(period/time.Second))
	}
	advance := func(taskID, worker string) application.RefreshOutcome {
		t.Helper()
		task, _, err := tasks.Claim(ctx, taskID, 1, worker, time.Minute)
		require.NoError(t, err)
		_, err = refresh.Advance(ctx, taskID, 1, "someone-else", task.InputDigest)
		require.ErrorIs(t, err, domain.ErrStaleExecution, "only the current claimant is answered")
		out, err := refresh.Advance(ctx, taskID, 1, worker, task.InputDigest)
		require.NoError(t, err)
		require.True(t, out.Completed)
		again, err := refresh.Advance(ctx, taskID, 1, worker, task.InputDigest)
		require.NoError(t, err)
		require.Equal(t, out, again, "one recorded observation per generation")
		return out
	}
	submit := func(taskID, worker string, out application.RefreshOutcome) domain.SubmitDecision {
		t.Helper()
		task, err := tasks.Get(ctx, taskID)
		require.NoError(t, err)
		dec, err := tasks.Submit(ctx, taskID, 1, domain.Submission{WorkerID: worker, InputDigest: task.InputDigest, Succeeded: true, ResultRef: out.ResultRef, ResultDigest: out.ResultDigest})
		require.NoError(t, err)
		return dec
	}

	t.Run("an unchanged server: requested once per period, accepted with the recorded result, still approved", func(t *testing.T) {
		n, err := refresh.Schedule(ctx, period, 50)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		n, err = refresh.Schedule(ctx, period, 50)
		require.NoError(t, err)
		require.Zero(t, n, "the same period answers the existing request")
		taskID := taskOf()
		out := advance(taskID, "w1")
		dec := submit(taskID, "w1", out)
		require.True(t, dec.Accepted)
		got, err := h.catalog.Get(ctx, manager, d.ServerID, d.Revision)
		require.NoError(t, err)
		require.Equal(t, domain.CatalogApproved, got.State)
	})

	t.Run("a submission other than the recorded observation is a profile mismatch", func(t *testing.T) {
		h.clock.Advance(period)
		_, err := refresh.Schedule(ctx, period, 50)
		require.NoError(t, err)
		taskID := taskOf()
		out := advance(taskID, "w2")
		out.ResultDigest = domain.DigestBytes([]byte("claimant's own idea"))
		dec := submit(taskID, "w2", out)
		require.False(t, dec.Accepted)
		require.Equal(t, domain.FailureProfileMismatch, dec.Task.FailureCode)
	})

	t.Run("a drifted server: the accepted refresh disables the revision before any call meets the drift", func(t *testing.T) {
		live := liveIssues("")
		live.Version = "1.5.0"
		live.Tools[0].Annotations = nil // readOnlyHint removed
		h.conn.set(issuesURL, live)
		defer h.conn.set(issuesURL, liveIssues(""))
		h.clock.Advance(period)
		n, err := refresh.Schedule(ctx, period, 50)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		taskID := taskOf()
		out := advance(taskID, "w3")
		got, err := h.catalog.Get(ctx, manager, d.ServerID, d.Revision)
		require.NoError(t, err)
		require.Equal(t, domain.CatalogApproved, got.State, "the owner acts on the accepted result, not on the read alone")
		dec := submit(taskID, "w3", out)
		require.True(t, dec.Accepted, "the grant was current at acceptance")
		got, err = h.catalog.Get(ctx, manager, d.ServerID, d.Revision)
		require.NoError(t, err)
		require.Equal(t, domain.CatalogDisabled, got.State)
		gr, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Contains(t, []domain.GrantState{domain.GrantRevoking, domain.GrantRevoked}, gr.State, "the revision's grants begin revocation")
		require.False(t, h.executable(t, g.GrantID, "tenant_a"))
		var reviewer, reason string
		require.NoError(t, h.store.Pool().QueryRow(ctx, "SELECT reviewer, reason_code FROM reviews WHERE server_id = $1 AND decision = 'disable'", d.ServerID).Scan(&reviewer, &reason))
		require.Equal(t, application.RefreshActor, reviewer)
		require.Equal(t, "REFRESH_DRIFT", reason)
		var drift string
		require.NoError(t, h.store.Pool().QueryRow(ctx, "SELECT drift_reason FROM catalog_refreshes WHERE task_id = $1", taskID).Scan(&drift))
		require.Contains(t, drift, "issues 1.4.0 -> issues 1.5.0")
		require.Contains(t, drift, "search_issues: annotations")
		n, err = refresh.Schedule(ctx, period, 50)
		require.NoError(t, err)
		require.Zero(t, n, "a disabled revision is refreshed no more")
	})
}
