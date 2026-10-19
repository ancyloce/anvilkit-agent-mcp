package application_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// revocationStage sums a barrier stage over the replicas' histograms: what
// Prometheus adds up.
func revocationStage(t *testing.T, stage string, replicas ...*application.Metrics) (count uint64, seconds float64) {
	t.Helper()
	for _, m := range replicas {
		var out dto.Metric
		require.NoError(t, m.RevocationSeconds.WithLabelValues(stage).(prometheus.Metric).Write(&out))
		count += out.GetHistogram().GetSampleCount()
		seconds += out.GetHistogram().GetSampleSum()
	}
	return count, seconds
}

// P3.6 (platform.md SLO row 3): each revocation observes its fence and its
// convergence once, from the revocation's commit, on whichever of two
// replicas commits the milestone — not while Control is down, not for a
// lost fence answer, not for a repeated command and not for the replica
// that loses the race.
func TestRevocationLatencyIsObservedOncePerMilestone(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()
	d := h.approved(t)
	other := application.NewMetrics(prometheus.NewRegistry())
	replica := application.NewGrants(h.store, h.authz, h.registry, h.clock, slog.New(slog.NewTextHandler(io.Discard, nil)), other)
	stage := func(name string) (uint64, float64) { return revocationStage(t, name, h.metrics, other) }

	t.Run("an active grant: the fence, then convergence", func(t *testing.T) {
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantActive, g.State)
		h.registry.set(func(f *fakeRegistry) { f.down = true })
		c := h.cmd(granter)
		r, _, err := h.grants.Revoke(ctx, c, granter, g.GrantID, 1, "compromised")
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoking, r.State)
		_, _, err = h.grants.Revoke(ctx, c, granter, g.GrantID, 1, "compromised")
		require.NoError(t, err)
		n, _ := stage("fenced")
		require.Zero(t, n, "nothing is fenced while Control is down")

		// Control installs the fence but its answer is lost.
		time.Sleep(100 * time.Millisecond)
		h.registry.set(func(f *fakeRegistry) { f.down = false; f.inFlight = 1; f.fault["begin"] = "lost" })
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		n, _ = stage("fenced")
		require.Zero(t, n, "a lost fence answer records nothing")

		// Both replicas reconcile at once: one records Control's fence.
		var wg sync.WaitGroup
		for _, gs := range []*application.Grants{h.grants, replica} {
			wg.Add(1)
			go func(gs *application.Grants) {
				defer wg.Done()
				_, err := gs.Reconcile(ctx, 0, 50)
				require.NoError(t, err)
			}(gs)
		}
		wg.Wait()
		mid, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, "converging", mid.ControlState)
		n, fenced := stage("fenced")
		require.Equal(t, uint64(1), n, "the fence is observed once across the replicas")
		require.GreaterOrEqual(t, fenced, 0.05, "from the revocation's commit to Control's fence")
		n, _ = stage("converged")
		require.Zero(t, n, "a sender still holds a permission")

		time.Sleep(100 * time.Millisecond)
		h.registry.set(func(f *fakeRegistry) { f.inFlight = 0 })
		_, err = replica.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		done, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoked, done.State)
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		_, _, err = h.grants.Revoke(ctx, c, granter, g.GrantID, 1, "compromised")
		require.NoError(t, err)
		n, converged := stage("converged")
		require.Equal(t, uint64(1), n, "REVOKED is observed once")
		require.Greater(t, converged, fenced, "convergence follows the fence")
		n, _ = stage("fenced")
		require.Equal(t, uint64(1), n)
	})

	t.Run("a grant revoked before its registration reaches both milestones in one commit", func(t *testing.T) {
		h.registry.set(func(f *fakeRegistry) { f.fault["register"] = "before" })
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantPending, g.State)
		r, _, err := h.grants.Revoke(ctx, h.cmd(granter), granter, g.GrantID, 1, "user")
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoked, r.State)
		n, _ := stage("fenced")
		require.Equal(t, uint64(2), n)
		n, _ = stage("converged")
		require.Equal(t, uint64(2), n)
	})
}
