package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/control"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// ReconcileCall is the operator entry point behind `anvilkit-agent-mcp
// reconcile <callId>` (P1.2, MCP-04): with the process's own configuration
// and workload identity it asks Control for the current record of the
// call's original dispatch and advances the call accordingly — an UNKNOWN
// call whose identity Control resolved (observed, or confirmed not sent)
// settles, which clears the RECOVERY_RESTRICTED hold on its server. It
// never sends anything upstream and needs no running MCP replica.
func ReconcileCall(ctx context.Context, callID string) (domain.Call, error) {
	gen, err := config.Load()
	if err != nil {
		return domain.Call{}, err
	}
	cfg := gen.Config
	if cfg.Control.Address == "" {
		return domain.Call{}, fmt.Errorf("no Control placement (control.address unset): the original identity cannot be queried")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return domain.Call{}, err
	}
	defer pool.Close()
	w, err := newWorkloadIdentity(cfg, log)
	if err != nil {
		return domain.Call{}, err
	}
	transport, err := w.controlTransport(cfg, log)
	if err != nil {
		return domain.Call{}, err
	}
	dispatch, err := control.Dial(cfg.Control.Address, cfg.Control.Timeout, transport)
	if err != nil {
		return domain.Call{}, err
	}
	defer dispatch.Close()
	calls := application.NewCalls(postgres.NewStore(pool), dispatch, map[string]application.Upstream{}, nil, nil,
		application.CallOptions{SendTimeout: cfg.Calls.SendTimeout, ReconcileAge: cfg.Calls.ReconcileAge}, application.SystemClock{},
		application.NewMetrics(prometheus.NewRegistry()), log)
	return calls.ReconcileCall(ctx, callID)
}
