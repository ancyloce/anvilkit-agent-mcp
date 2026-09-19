package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// runtime is what one configuration generation owns: its pool and, when
// enabled, its forwarder (bound to that pool and its own NATS connection).
type runtime struct {
	gen       config.Generation
	pool      *pgxpool.Pool
	forwarder *outbox.Forwarder
	fwdCancel context.CancelFunc
	fwdDone   chan struct{}
}

// Generations builds, probes, publishes and drains configuration
// generations (DD-09 §4): a candidate is loaded from the same inputs as the
// first one, its clients are constructed off-path and probed, and only
// then does the atomic swap make it the active generation; the previous
// generation's forwarder stops and its pool drains within the limit.
// Rejected candidates leave nothing behind and the active generation
// untouched. New admissions read the active generation; leases and
// requests already made keep what they froze.
type Generations struct {
	path    string
	environ []string
	store   *postgres.Store
	tasks   *application.Tasks
	metrics *application.Metrics
	log     *slog.Logger

	mu     sync.Mutex
	active *runtime
	number uint64
}

func newGenerations(path string, environ []string, first config.Generation, store *postgres.Store, tasks *application.Tasks, metrics *application.Metrics, log *slog.Logger) *Generations {
	return &Generations{path: path, environ: environ, store: store, tasks: tasks, metrics: metrics, log: log, number: first.Number}
}

// Active is the active generation.
func (g *Generations) Active() config.Generation {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == nil {
		return config.Generation{}
	}
	return g.active.gen
}

// buildRuntime constructs the clients of a generation off-path and probes
// them; on any failure everything it created is closed.
func buildRuntime(ctx context.Context, gen config.Generation, metrics *application.Metrics, log *slog.Logger) (rt *runtime, err error) {
	cfg := gen.Config
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	poolCfg.MaxConns = cfg.Database.MaxConn
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			pool.Close()
		}
	}()
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = pool.Ping(probe); err != nil {
		return nil, fmt.Errorf("database probe: %w", err)
	}
	rt = &runtime{gen: gen, pool: pool}
	if cfg.Outbox.ForwarderEnabled {
		o := cfg.Outbox
		rt.forwarder, err = outbox.NewForwarder(pool, outbox.ForwarderConfig{
			ConsumerGroup: o.ConsumerGroup, PollInterval: o.PollInterval, AckDeadline: o.AckDeadline, ResendInterval: o.ResendInterval, BatchSize: o.BatchSize,
			NATSURL: o.NATS.URL, NATSName: o.NATS.Name, PublishTimeout: o.NATS.PublishTimeout, CloseTimeout: cfg.Reload.DrainLimit,
		}, log, metrics.Forwarded, metrics.ForwardFailures)
		if err != nil {
			return nil, fmt.Errorf("forwarder: %w", err)
		}
	}
	return rt, nil
}

func (rt *runtime) startForwarder(log *slog.Logger) {
	if rt.forwarder == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt.fwdCancel = cancel
	rt.fwdDone = make(chan struct{})
	go func() {
		defer close(rt.fwdDone)
		if err := rt.forwarder.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("outbox forwarder stopped", "generation", rt.gen.Number, "error", err)
		}
	}()
}

// retire stops the generation's forwarder and drains its pool within the
// limit; a pool still holding connections after the limit is reported as
// a forced close (the connections belong to transactions that will fail
// when they next touch it).
func (rt *runtime) retire(limit time.Duration, log *slog.Logger) (forced bool) {
	if rt.forwarder != nil {
		rt.fwdCancel()
		_ = rt.forwarder.Close()
		select {
		case <-rt.fwdDone:
		case <-time.After(limit):
			forced = true
		}
	}
	done := make(chan struct{})
	go func() { rt.pool.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(limit):
		forced = true
		log.Warn("generation pool did not drain within the limit", "generation", rt.gen.Number, "acquired", rt.pool.Stat().AcquiredConns())
	}
	return forced
}

// activate publishes a built runtime as the active generation and retires
// the previous one.
func (g *Generations) activate(rt *runtime) {
	g.mu.Lock()
	previous := g.active
	g.active = rt
	g.mu.Unlock()
	rt.startForwarder(g.log)
	g.store.Swap(rt.pool)
	g.tasks.SetBounds(bounds(rt.gen.Config))
	g.tasks.SetExpiry(rt.gen.ExpiresAt)
	g.metrics.ConfigGeneration.Set(float64(rt.gen.Number))
	g.log.Info("configuration generation active", "generation", rt.gen.Number, "digest", rt.gen.Digest, "secretRevision", rt.gen.SecretRevision, "apolloRelease", rt.gen.ApolloRelease, "profiles", rt.gen.Profiles)
	if previous != nil {
		started := time.Now()
		forced := previous.retire(rt.gen.Config.Reload.DrainLimit, g.log)
		g.log.Info("previous generation drained", "generation", previous.gen.Number, "seconds", time.Since(started).Seconds(), "forced", forced)
	}
}

// Reload loads a candidate from the current inputs and, when its inputs
// differ from the active generation's, builds, probes and publishes it.
func (g *Generations) Reload(ctx context.Context) (changed bool, err error) {
	active := g.Active()
	candidate, err := config.LoadFrom(g.path, g.environ, g.number+1)
	if err != nil {
		g.metrics.ConfigRejections.Inc()
		return false, err
	}
	if candidate.Inputs() == active.Inputs() {
		return false, nil
	}
	rt, err := buildRuntime(ctx, candidate, g.metrics, g.log)
	if err != nil {
		g.metrics.ConfigRejections.Inc()
		return false, fmt.Errorf("generation %d rejected: %w", candidate.Number, err)
	}
	g.number = candidate.Number
	g.activate(rt)
	g.metrics.ConfigRotations.Inc()
	return true, nil
}

// Watch re-reads the inputs at the reload interval until ctx ends.
func (g *Generations) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := g.Reload(ctx); err != nil {
				g.log.Warn("configuration candidate rejected; the active generation stays", "error", err)
			}
		}
	}
}

// Shutdown retires the active generation (the last step of the process).
func (g *Generations) Shutdown(limit time.Duration) (forced bool) {
	g.mu.Lock()
	rt := g.active
	g.active = nil
	g.mu.Unlock()
	if rt == nil {
		return false
	}
	return rt.retire(limit, g.log)
}

func bounds(c config.Config) domain.Bounds {
	return domain.Bounds{MaxInputBytes: c.Tasks.MaxInputBytes, MaxLease: c.Tasks.MaxLease, RetryDelay: c.Tasks.RetryDelay, MaxAttempts: c.Tasks.MaxAttempts}
}

// configPath is the reviewed file of this process.
func configPath() string {
	if p := os.Getenv(config.EnvConfigFile); p != "" {
		return p
	}
	return config.DefaultConfigFile
}
